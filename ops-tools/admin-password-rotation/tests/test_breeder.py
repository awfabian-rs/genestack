from __future__ import annotations

import base64
from dataclasses import dataclass
from typing import cast
from uuid import UUID

import pytest

from admin_password_rotation.breeder import (
    PROVENANCE_GENERATION, PROVENANCE_STAGE, PROVENANCE_STAGE_PENDING_KEYSTONE,
    PROVENANCE_TRANSACTION, BreederError, BreederErrorCode, BreederProvenance,
    BreederReference, KubernetesApiBreederSecretClient,
)
from admin_password_rotation.model import CredentialGeneration, SecretValue


PASSWORD = SecretValue(b"Old_0123456789abcdefghijklmnop")
NEW_PASSWORD = SecretValue(b"New_0123456789abcdefghijklmnop")
TRANSACTION = UUID("11111111-1111-4111-8111-111111111111")


class Serializer:
    def sanitize_for_serialization(self, value: object) -> object:
        return value


@dataclass
class ApiError(Exception):
    status: object


class Api:
    def __init__(self) -> None:
        self.resource: dict[str, object] = {
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": {
                "namespace": "openstack",
                "name": "keystone-admin",
                "uid": "breeder-uid",
                "resourceVersion": "42",
                "annotations": {"example.org/keep": "unchanged"},
            },
            "data": {
                "password": base64.b64encode(PASSWORD.reveal()).decode(),
                "unrelated": base64.b64encode(b"preserve-me").decode(),
            },
        }
        self.patch: list[dict[str, object]] | None = None
        self.error: Exception | None = None

    def read_namespaced_secret(
        self, name: str, namespace: str, **kwargs: object,
    ) -> object:
        assert (namespace, name) == ("openstack", "keystone-admin")
        assert kwargs["_request_timeout"] == 60.0
        return self.resource

    def patch_namespaced_secret(
        self, name: str, namespace: str, body: list[dict[str, object]],
        **kwargs: object,
    ) -> object:
        assert (namespace, name) == ("openstack", "keystone-admin")
        assert kwargs["_content_type"] == "application/json-patch+json"
        self.patch = body
        if self.error is not None:
            raise self.error
        return {}


def client(api: Api) -> KubernetesApiBreederSecretClient:
    return KubernetesApiBreederSecretClient(api, Serializer())


def test_read_and_patch_are_exact_uid_resource_version_conditional_and_narrow() -> None:
    api = Api()
    boundary = client(api)
    observed = boundary.read(BreederReference())
    generation = CredentialGeneration.from_secret(NEW_PASSWORD)

    boundary.conditional_stage(
        observed,
        password=NEW_PASSWORD,
        provenance=BreederProvenance(TRANSACTION, generation),
    )

    assert api.patch is not None
    assert api.patch[:3] == [
        {"op": "test", "path": "/metadata/uid", "value": "breeder-uid"},
        {"op": "test", "path": "/metadata/resourceVersion", "value": "42"},
        {
            "op": "replace",
            "path": "/data/password",
            "value": base64.b64encode(NEW_PASSWORD.reveal()).decode(),
        },
    ]
    paths = {str(item["path"]): item for item in api.patch}
    assert paths["/metadata/annotations/rotation.genestack.org~1transaction-id"]["value"] == str(TRANSACTION)
    assert paths["/metadata/annotations/rotation.genestack.org~1new-admin-sha256"]["value"] == generation.value
    assert paths["/metadata/annotations/rotation.genestack.org~1stage"]["value"] == PROVENANCE_STAGE_PENDING_KEYSTONE
    assert all(item["path"] != "/data/unrelated" for item in api.patch)
    assert all(item["path"] != "/metadata/annotations/example.org~1keep" for item in api.patch)
    assert observed.get("unrelated") == SecretValue(b"preserve-me")
    assert observed.annotation("example.org/keep") == "unchanged"


def test_provenance_constants_are_the_single_intended_representation() -> None:
    generation = CredentialGeneration.from_secret(NEW_PASSWORD)
    values = {
        item.key: item.value
        for item in BreederProvenance(TRANSACTION, generation).annotations()
    }
    assert values == {
        PROVENANCE_TRANSACTION: str(TRANSACTION),
        PROVENANCE_GENERATION: generation.value,
        PROVENANCE_STAGE: PROVENANCE_STAGE_PENDING_KEYSTONE,
    }


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        (409, BreederErrorCode.CONDITIONAL_REJECTED),
        (422, BreederErrorCode.CONDITIONAL_REJECTED),
        (500, BreederErrorCode.OUTCOME_AMBIGUOUS),
        (503, BreederErrorCode.OUTCOME_AMBIGUOUS),
        (403, BreederErrorCode.FAILURE),
    ],
)
def test_patch_failures_are_typed_without_payloads(
    status: int, expected: BreederErrorCode,
) -> None:
    api = Api()
    api.error = ApiError(status)
    boundary = client(api)
    observed = boundary.read(BreederReference())
    with pytest.raises(BreederError) as raised:
        boundary.conditional_stage(
            observed,
            password=NEW_PASSWORD,
            provenance=BreederProvenance(
                TRANSACTION, CredentialGeneration.from_secret(NEW_PASSWORD),
            ),
        )
    assert raised.value.kind is expected
    assert NEW_PASSWORD.reveal().decode() not in str(raised.value) + repr(raised.value)


def test_missing_annotations_are_added_before_individual_provenance_keys() -> None:
    api = Api()
    metadata = cast(dict[str, object], api.resource["metadata"])
    metadata.pop("annotations")
    boundary = client(api)
    observed = boundary.read(BreederReference())
    boundary.conditional_stage(
        observed,
        password=NEW_PASSWORD,
        provenance=BreederProvenance(
            TRANSACTION, CredentialGeneration.from_secret(NEW_PASSWORD),
        ),
    )
    assert api.patch is not None
    assert {"op": "add", "path": "/metadata/annotations", "value": {}} in api.patch
