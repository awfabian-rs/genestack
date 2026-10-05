from __future__ import annotations

import json
from dataclasses import asdict, replace
from datetime import datetime, timezone
from enum import Enum
from uuid import UUID

import pytest

from admin_password_rotation.a_state import (
    AAuthenticationCandidate, AAuthenticationObservation, AReconciliationReason,
    AReconciliationResult, AReconciliationStatus, ARotationInputs, ARotationObservation,
    ARotationObservedState, classify_a_rotation, observe_a_rotation_state,
)
from admin_password_rotation.keystone import (
    FakeKeystoneClient, KeystoneAuthenticationResult,
    KeystoneAuthenticationStatus, KeystoneAuthIndeterminate, KeystoneAuthSuccess,
    KeystoneIndeterminateReason, KeystonePasswordAuthRequest,
    KeystoneUserObservation,
)
from admin_password_rotation.model import (
    ConfigurationDigest, CredentialGeneration, CredentialMutationIntent,
    CredentialMutationStep, ExecutionIdentity, IntentEffectState, LockoutChangeState,
    LockoutState, PasswordSafeState, PropagationState, PropagationWave,
    ResolvedKeystoneIdentities, RotationPhase, RotationTransaction, SecretInventory,
    SecretValue, TransactionStatus, VerificationResult, VerificationStatus,
)
from admin_password_rotation.passwordsafe import (
    FakePasswordSafeClient, IdentityAccess, PasswordSafeCredential,
)
from tests.helpers import PASSWORD, contract, secret


NOW = datetime(2026, 10, 5, 12, 0, tzinfo=timezone.utc)
A_OLD = SecretValue(PASSWORD)
A_NEW = SecretValue(b"SYNTHETIC_Admin_New_000000000001")
A_UNKNOWN = SecretValue(b"SYNTHETIC_Admin_Unknown_0000001")
A_OTHER = SecretValue(b"SYNTHETIC_Admin_Other_000000003")
NEW_GENERATION = CredentialGeneration.from_secret(A_NEW)
OLD_GENERATION = CredentialGeneration.from_secret(A_OLD)
KEYSTONE_IDS = ResolvedKeystoneIdentities(
    admin_user_id="admin-user",
    breakglass_user_id="breakglass-user",
    user_domain_id="default-domain",
    project_id="admin-project",
    project_domain_id="default-domain",
    role_id="admin-role",
)


def transaction(
    *,
    intended: CredentialGeneration | None,
    intent_step: CredentialMutationStep | None = None,
    effect_state: IntentEffectState = IntentEffectState.UNKNOWN,
    include_stable_generation: bool = True,
) -> RotationTransaction:
    intent = None
    if intent_step is not None:
        assert intended is not None
        intent = CredentialMutationIntent(
            intent_step, None, (), intended, effect_state, None, None,
        )
    verifications: tuple[VerificationResult, ...] = ()
    if include_stable_generation:
        verifications = (VerificationResult(
            check_id="stable-a",
            phase=RotationPhase.PREPARE_B,
            status=VerificationStatus.SUCCESS,
            checked_at=NOW,
            detail_code="freshly-verified",
            target_uid="fixture-keystone-admin",
            credential_generation=OLD_GENERATION,
        ),)
    return RotationTransaction(
        transaction_id=UUID("11111111-1111-4111-8111-111111111111"),
        request_id=UUID("22222222-2222-4222-8222-222222222222"),
        execution=ExecutionIdentity(
            UUID("33333333-3333-4333-8333-333333333333"), None,
        ),
        configuration_digest=ConfigurationDigest("sha256:" + "c" * 64),
        keystone=KEYSTONE_IDS,
        created_at=NOW,
        updated_at=NOW,
        phase=RotationPhase.ROTATE_A,
        status=TransactionStatus.ACTIVE,
        last_error=None,
        new_a_sha256=intended,
        new_b_sha256=CredentialGeneration("sha256:" + "b" * 64),
        passwordsafe=PasswordSafeState(
            configured_a_record_id=101,
            configured_b_record_id=202,
            observed_a_record_id=101,
            observed_b_record_id=202,
            original_a_version=7,
            observed_a_version=7,
            observed_b_version=4,
        ),
        credential_mutation_intent=intent,
        propagation=PropagationState(
            PropagationWave((), ()), PropagationWave((), ()),
        ),
        lockout=LockoutState(
            initial_ignore_lockout_failure_attempts=False,
            suppression=LockoutChangeState.EFFECT_OBSERVED,
            restoration=LockoutChangeState.NOT_INTENDED,
            latest_ignore_lockout_failure_attempts=True,
            restore_required=True,
        ),
        verifications=verifications,
    )


def inventory_with_breeder(
    password: SecretValue,
    *,
    uid: str = "fixture-keystone-admin",
) -> SecretInventory:
    return SecretInventory("openstack", "456", (
        replace(secret("keystone-admin", {"password": password.reveal()}), uid=uid),
        secret("consumer", {
            "OS_USERNAME": b"admin",
            "OS_PASSWORD": A_OLD.reveal(),
        }),
    ))


def passwordsafe_with(value: SecretValue, *, version: int = 7) -> FakePasswordSafeClient:
    client = FakePasswordSafeClient()
    client.add(PasswordSafeCredential(10, 101, "admin", version, value))
    return client


def keystone_with(value: SecretValue) -> FakeKeystoneClient:
    client = FakeKeystoneClient(
        project_id="admin-project",
        project_name="admin",
        project_domain_id="default-domain",
    )
    client.add_user(KeystoneUserObservation(
        user_id="admin-user",
        name="admin",
        domain_id="default-domain",
        enabled=True,
        default_project_id="admin-project",
        ignore_lockout_failure_attempts=True,
    ), value)
    return client


def inputs(
    state: RotationTransaction,
    *,
    breeder: SecretValue,
    breeder_uid: str = "fixture-keystone-admin",
) -> ARotationInputs:
    return ARotationInputs(
        transaction=state,
        contract=contract(),
        inventory=inventory_with_breeder(breeder, uid=breeder_uid),
        passwordsafe_access=IdentityAccess(
            datetime(2030, 1, 1, tzinfo=timezone.utc),
            SecretValue(b"redacted-passwordsafe-token"),
        ),
        passwordsafe_project_id=10,
    )


def observe(
    state: RotationTransaction,
    *,
    passwordsafe_value: SecretValue,
    breeder: SecretValue,
    keystone: FakeKeystoneClient,
    passwordsafe_version: int = 7,
    breeder_uid: str = "fixture-keystone-admin",
) -> tuple[AReconciliationResult, FakePasswordSafeClient]:
    ps = passwordsafe_with(passwordsafe_value, version=passwordsafe_version)
    result = observe_a_rotation_state(
        inputs(state, breeder=breeder, breeder_uid=breeder_uid),
        passwordsafe=ps,
        keystone=keystone,
        clock=lambda: NOW,
    )
    assert ps.update_calls == []
    assert keystone.password_update_calls == []
    assert keystone.lockout_update_calls == []
    return result, ps


def assert_state(
    result: AReconciliationResult,
    expected: ARotationObservedState,
) -> None:
    assert result.status is AReconciliationStatus.VALID
    assert result.state is expected


def test_a0_equal_authorities_and_fresh_expected_admin_authentication() -> None:
    result, _ = observe(
        transaction(intended=None),
        passwordsafe_value=A_OLD,
        breeder=A_OLD,
        keystone=keystone_with(A_OLD),
    )
    assert_state(result, ARotationObservedState.A0)


@pytest.mark.parametrize(
    ("alteration", "status", "reason"),
    [
        ("rejected", AReconciliationStatus.INVALID, AReconciliationReason.CURRENT_CREDENTIAL_REJECTED),
        ("indeterminate", AReconciliationStatus.INDETERMINATE, AReconciliationReason.AUTHENTICATION_INDETERMINATE),
        ("wrong_user", AReconciliationStatus.INVALID, AReconciliationReason.ADMIN_IDENTITY_SCOPE_MISMATCH),
        ("wrong_project", AReconciliationStatus.INVALID, AReconciliationReason.ADMIN_IDENTITY_SCOPE_MISMATCH),
        ("wrong_domain", AReconciliationStatus.INVALID, AReconciliationReason.ADMIN_IDENTITY_SCOPE_MISMATCH),
        ("wrong_role", AReconciliationStatus.INVALID, AReconciliationReason.ADMIN_IDENTITY_SCOPE_MISMATCH),
    ],
)
def test_a0_authentication_failures_block(
    alteration: str,
    status: AReconciliationStatus,
    reason: AReconciliationReason,
) -> None:
    keystone = AlteredKeystone(A_OLD, alteration)
    result, _ = observe(
        transaction(intended=None),
        passwordsafe_value=A_OLD,
        breeder=A_OLD,
        keystone=keystone,
    )
    assert result.status is status
    assert result.reason is reason


def test_a1_old_works_and_exact_intended_breeder_new_rejects() -> None:
    result, _ = observe(
        transaction(intended=NEW_GENERATION),
        passwordsafe_value=A_OLD,
        breeder=A_NEW,
        keystone=keystone_with(A_OLD),
    )
    assert_state(result, ARotationObservedState.A1)


def test_a2_new_works_and_passwordsafe_remains_established_old() -> None:
    result, _ = observe(
        transaction(intended=NEW_GENERATION),
        passwordsafe_value=A_OLD,
        breeder=A_NEW,
        keystone=keystone_with(A_NEW),
    )
    assert_state(result, ARotationObservedState.A2)


def test_a3_both_authorities_match_intended_and_new_authenticates() -> None:
    result, _ = observe(
        transaction(intended=NEW_GENERATION),
        passwordsafe_value=A_NEW,
        passwordsafe_version=8,
        breeder=A_NEW,
        keystone=keystone_with(A_NEW),
    )
    assert_state(result, ARotationObservedState.A3)


def test_recreated_breeder_blocks_a0_before_authentication() -> None:
    keystone = TrackingKeystone(A_OLD)
    result, _ = observe(
        transaction(intended=None),
        passwordsafe_value=A_OLD,
        breeder=A_OLD,
        breeder_uid="replacement-keystone-admin",
        keystone=keystone,
    )
    assert result.status is AReconciliationStatus.INVALID
    assert result.reason is AReconciliationReason.BREEDER_IDENTITY_CHANGED
    assert result.state is None
    assert keystone.auth_generations == []


@pytest.mark.parametrize("accepted", [A_OLD, A_NEW])
def test_recreated_breeder_blocks_a1_or_a2_before_authentication(
    accepted: SecretValue,
) -> None:
    keystone = TrackingKeystone(accepted)
    result, _ = observe(
        transaction(intended=NEW_GENERATION),
        passwordsafe_value=A_OLD,
        breeder=A_NEW,
        breeder_uid="replacement-keystone-admin",
        keystone=keystone,
    )
    assert result.status is AReconciliationStatus.INVALID
    assert result.reason is AReconciliationReason.BREEDER_IDENTITY_CHANGED
    assert result.state is None
    assert keystone.auth_generations == []


def test_recreated_breeder_blocks_a3_before_authentication() -> None:
    keystone = TrackingKeystone(A_NEW)
    result, _ = observe(
        transaction(intended=NEW_GENERATION),
        passwordsafe_value=A_NEW,
        passwordsafe_version=8,
        breeder=A_NEW,
        breeder_uid="replacement-keystone-admin",
        keystone=keystone,
    )
    assert result.status is AReconciliationStatus.INVALID
    assert result.reason is AReconciliationReason.BREEDER_IDENTITY_CHANGED
    assert result.state is None
    assert keystone.auth_generations == []


@pytest.mark.parametrize(
    ("alteration", "status", "reason"),
    [
        ("rejected", AReconciliationStatus.INVALID, AReconciliationReason.NEW_CREDENTIAL_REJECTED),
        ("indeterminate", AReconciliationStatus.INDETERMINATE, AReconciliationReason.AUTHENTICATION_INDETERMINATE),
    ],
)
def test_a3_authentication_failure_blocks(
    alteration: str,
    status: AReconciliationStatus,
    reason: AReconciliationReason,
) -> None:
    result, _ = observe(
        transaction(intended=NEW_GENERATION),
        passwordsafe_value=A_NEW,
        passwordsafe_version=8,
        breeder=A_NEW,
        keystone=AlteredKeystone(A_NEW, alteration),
    )
    assert result.status is status
    assert result.reason is reason


@pytest.mark.parametrize(
    ("passwordsafe_value", "passwordsafe_version", "breeder", "reason"),
    [
        (A_NEW, 8, A_OLD, AReconciliationReason.PASSWORDSAFE_NEW_BREEDER_OLD),
        (A_UNKNOWN, 8, A_NEW, AReconciliationReason.PASSWORDSAFE_UNKNOWN_BREEDER_NEW),
        (A_NEW, 8, A_UNKNOWN, AReconciliationReason.PASSWORDSAFE_NEW_BREEDER_UNKNOWN),
        (A_UNKNOWN, 8, A_UNKNOWN, AReconciliationReason.EQUAL_UNKNOWN_GENERATION),
        (A_UNKNOWN, 8, A_OTHER, AReconciliationReason.DIVERGENT_UNKNOWN_GENERATIONS),
    ],
)
def test_impossible_or_unknown_topologies_are_invalid_without_authentication(
    passwordsafe_value: SecretValue,
    passwordsafe_version: int,
    breeder: SecretValue,
    reason: AReconciliationReason,
) -> None:
    keystone = TrackingKeystone(A_OLD)
    result, _ = observe(
        transaction(intended=NEW_GENERATION),
        passwordsafe_value=passwordsafe_value,
        passwordsafe_version=passwordsafe_version,
        breeder=breeder,
        keystone=keystone,
    )
    assert result.status is AReconciliationStatus.INVALID
    assert result.reason is reason
    assert keystone.auth_generations == []


def test_missing_breeder_is_typed_invalid_and_read_only() -> None:
    state = transaction(intended=NEW_GENERATION)
    base = inputs(state, breeder=A_NEW)
    observed_inputs = replace(
        base,
        inventory=SecretInventory("openstack", "456", (
            secret("consumer", {
                "OS_USERNAME": b"admin",
                "OS_PASSWORD": A_OLD.reveal(),
            }),
        )),
    )
    passwordsafe = passwordsafe_with(A_OLD)
    keystone = TrackingKeystone(A_OLD)
    result = observe_a_rotation_state(
        observed_inputs,
        passwordsafe=passwordsafe,
        keystone=keystone,
        clock=lambda: NOW,
    )
    assert result.status is AReconciliationStatus.INVALID
    assert result.reason is AReconciliationReason.BREEDER_MISSING
    assert passwordsafe.update_calls == []
    assert keystone.auth_generations == []


def test_malformed_breeder_is_typed_invalid_and_read_only() -> None:
    state = transaction(intended=NEW_GENERATION)
    base = inputs(state, breeder=A_NEW)
    observed_inputs = replace(
        base,
        inventory=SecretInventory("openstack", "456", (
            secret("keystone-admin", {"unrelated": A_NEW.reveal()}),
        )),
    )
    passwordsafe = passwordsafe_with(A_OLD)
    keystone = TrackingKeystone(A_OLD)
    result = observe_a_rotation_state(
        observed_inputs,
        passwordsafe=passwordsafe,
        keystone=keystone,
        clock=lambda: NOW,
    )
    assert result.status is AReconciliationStatus.INVALID
    assert result.reason is AReconciliationReason.BREEDER_MALFORMED
    assert passwordsafe.update_calls == []
    assert keystone.auth_generations == []


def test_passwordsafe_record_mismatch_is_typed_invalid_and_read_only() -> None:
    state = transaction(intended=NEW_GENERATION)
    passwordsafe = FakePasswordSafeClient()
    passwordsafe.add(PasswordSafeCredential(10, 101, "not-admin", 7, A_OLD))
    keystone = TrackingKeystone(A_OLD)
    result = observe_a_rotation_state(
        inputs(state, breeder=A_NEW),
        passwordsafe=passwordsafe,
        keystone=keystone,
        clock=lambda: NOW,
    )
    assert result.status is AReconciliationStatus.INVALID
    assert result.reason is AReconciliationReason.PASSWORDSAFE_RECORD_INVALID
    assert passwordsafe.update_calls == []
    assert keystone.auth_generations == []


def test_malformed_passwordsafe_version_is_typed_invalid_and_read_only() -> None:
    keystone = TrackingKeystone(A_OLD)
    result, passwordsafe = observe(
        transaction(intended=NEW_GENERATION),
        passwordsafe_value=A_OLD,
        passwordsafe_version=0,
        breeder=A_NEW,
        keystone=keystone,
    )
    assert result.status is AReconciliationStatus.INVALID
    assert result.reason is AReconciliationReason.PASSWORDSAFE_RECORD_INVALID
    assert passwordsafe.update_calls == []
    assert keystone.auth_generations == []


def test_changed_breeder_must_match_intended_generation_exactly() -> None:
    result, _ = observe(
        transaction(intended=NEW_GENERATION),
        passwordsafe_value=A_OLD,
        breeder=A_UNKNOWN,
        keystone=keystone_with(A_OLD),
    )
    assert result.status is AReconciliationStatus.INVALID
    assert result.reason is AReconciliationReason.DIVERGENT_UNKNOWN_GENERATIONS


def test_original_passwordsafe_version_does_not_make_unrelated_value_old() -> None:
    result, _ = observe(
        transaction(intended=NEW_GENERATION),
        passwordsafe_value=A_UNKNOWN,
        passwordsafe_version=7,
        breeder=A_NEW,
        keystone=keystone_with(A_OLD),
    )
    assert result.status is AReconciliationStatus.INVALID
    assert result.reason is AReconciliationReason.PASSWORDSAFE_UNKNOWN_BREEDER_NEW


def test_breeder_new_but_neither_candidate_authenticates_is_invalid() -> None:
    result, _ = observe(
        transaction(intended=NEW_GENERATION),
        passwordsafe_value=A_OLD,
        breeder=A_NEW,
        keystone=keystone_with(A_UNKNOWN),
    )
    assert result.status is AReconciliationStatus.INVALID
    assert result.reason is AReconciliationReason.NO_VALID_ADMIN_CREDENTIAL


def test_indeterminate_new_auth_does_not_become_a1_from_working_old() -> None:
    keystone = AlteredKeystone(A_OLD, "first_indeterminate")
    result, _ = observe(
        transaction(intended=NEW_GENERATION),
        passwordsafe_value=A_OLD,
        breeder=A_NEW,
        keystone=keystone,
    )
    assert result.status is AReconciliationStatus.INDETERMINATE
    assert result.reason is AReconciliationReason.AUTHENTICATION_INDETERMINATE
    assert keystone.auth_generations == [NEW_GENERATION]


def test_both_old_and_new_success_is_anomalous() -> None:
    keystone = DualPasswordKeystone(A_OLD, A_NEW)
    result, _ = observe(
        transaction(intended=NEW_GENERATION),
        passwordsafe_value=A_OLD,
        breeder=A_NEW,
        keystone=keystone,
    )
    assert result.status is AReconciliationStatus.INVALID
    assert result.reason is AReconciliationReason.BOTH_OLD_AND_NEW_ACCEPTED


def test_a2_live_observation_blocks_when_old_authentication_is_indeterminate() -> None:
    keystone = AlteredKeystone(A_NEW, "second_indeterminate")
    result, _ = observe(
        transaction(intended=NEW_GENERATION),
        passwordsafe_value=A_OLD,
        breeder=A_NEW,
        keystone=keystone,
    )
    assert result.status is AReconciliationStatus.INDETERMINATE
    assert result.reason is AReconciliationReason.AUTHENTICATION_INDETERMINATE
    assert result.state is None
    assert keystone.auth_generations == [NEW_GENERATION, OLD_GENERATION]


def test_a2_is_indeterminate_when_old_authentication_is_indeterminate() -> None:
    observation = ARotationObservation(
        passwordsafe_record_id=101,
        passwordsafe_version=7,
        passwordsafe_generation=OLD_GENERATION,
        breeder_uid="breeder-uid",
        breeder_generation=NEW_GENERATION,
        passwordsafe_and_breeder_equal=False,
        passwordsafe_is_established_old=True,
        breeder_is_established_old=False,
        intended_generation=NEW_GENERATION,
        authentications=(
            AAuthenticationObservation(
                AAuthenticationCandidate.NEW,
                KeystoneAuthenticationStatus.SUCCESS,
                True,
                None,
            ),
            AAuthenticationObservation(
                AAuthenticationCandidate.OLD,
                KeystoneAuthenticationStatus.INDETERMINATE,
                None,
                KeystoneIndeterminateReason.DEPENDENCY_FAILURE,
            ),
        ),
    )
    result = classify_a_rotation(observation)
    assert result.status is AReconciliationStatus.INDETERMINATE
    assert result.reason is AReconciliationReason.AUTHENTICATION_INDETERMINATE
    assert result.state is None


def test_progress_pending_does_not_hide_already_staged_breeder() -> None:
    state = transaction(
        intended=NEW_GENERATION,
        intent_step=CredentialMutationStep.STAGE_A_BREEDER,
        effect_state=IntentEffectState.UNKNOWN,
    )
    result, _ = observe(
        state,
        passwordsafe_value=A_OLD,
        breeder=A_NEW,
        keystone=keystone_with(A_OLD),
    )
    assert_state(result, ARotationObservedState.A1)


def test_recorded_keystone_reset_success_does_not_override_fresh_rejection() -> None:
    state = transaction(
        intended=NEW_GENERATION,
        intent_step=CredentialMutationStep.RESET_A_KEYSTONE,
        effect_state=IntentEffectState.OBSERVED,
    )
    result, _ = observe(
        state,
        passwordsafe_value=A_OLD,
        breeder=A_NEW,
        keystone=keystone_with(A_OLD),
    )
    assert_state(result, ARotationObservedState.A1)


def test_unresolved_passwordsafe_progress_does_not_hide_observed_a3() -> None:
    state = transaction(
        intended=NEW_GENERATION,
        intent_step=CredentialMutationStep.UPDATE_A_PASSWORDSAFE,
        effect_state=IntentEffectState.DISPATCH_UNRESOLVED,
    )
    result, _ = observe(
        state,
        passwordsafe_value=A_NEW,
        passwordsafe_version=8,
        breeder=A_NEW,
        keystone=keystone_with(A_NEW),
    )
    assert_state(result, ARotationObservedState.A3)


def test_intended_generation_can_still_observe_known_prestage_a0() -> None:
    result, _ = observe(
        transaction(intended=NEW_GENERATION),
        passwordsafe_value=A_OLD,
        breeder=A_OLD,
        keystone=keystone_with(A_OLD),
    )
    assert_state(result, ARotationObservedState.A0)


def test_a0_requires_the_stable_a_credential_generation() -> None:
    keystone = TrackingKeystone(A_UNKNOWN)
    result, _ = observe(
        transaction(intended=None),
        passwordsafe_value=A_UNKNOWN,
        passwordsafe_version=8,
        breeder=A_UNKNOWN,
        keystone=keystone,
    )
    assert result.status is AReconciliationStatus.INVALID
    assert result.reason is AReconciliationReason.EQUAL_UNKNOWN_GENERATION
    assert keystone.auth_generations == []


def test_missing_stable_a_authority_is_invalid() -> None:
    keystone = TrackingKeystone(A_UNKNOWN)
    result, _ = observe(
        transaction(
            intended=NEW_GENERATION,
            include_stable_generation=False,
        ),
        passwordsafe_value=A_UNKNOWN,
        passwordsafe_version=8,
        breeder=A_UNKNOWN,
        keystone=keystone,
    )
    assert result.status is AReconciliationStatus.INVALID
    assert result.reason is AReconciliationReason.STABLE_A_AUTHORITY_INVALID
    assert keystone.auth_generations == []


def test_observation_and_result_representations_are_secret_free() -> None:
    old_sentinel = A_OLD.reveal().decode("utf-8")
    new_sentinel = A_NEW.reveal().decode("utf-8")
    result, _ = observe(
        transaction(intended=NEW_GENERATION),
        passwordsafe_value=A_OLD,
        breeder=A_NEW,
        keystone=keystone_with(A_OLD),
    )
    rendered = repr(result)
    serialized = json.dumps(
        asdict(result),
        default=lambda item: item.value if isinstance(item, Enum) else str(item),
        sort_keys=True,
    )
    assert old_sentinel not in rendered + serialized
    assert new_sentinel not in rendered + serialized


class TrackingKeystone(FakeKeystoneClient):
    def __init__(self, accepted: SecretValue) -> None:
        super().__init__(
            project_id="admin-project",
            project_name="admin",
            project_domain_id="default-domain",
        )
        self.add_user(KeystoneUserObservation(
            "admin-user", "admin", "default-domain", True,
            "admin-project", True,
        ), accepted)
        self.auth_generations: list[CredentialGeneration] = []

    def authenticate_password(
        self, request: KeystonePasswordAuthRequest,
    ) -> KeystoneAuthenticationResult:
        self.auth_generations.append(CredentialGeneration.from_secret(request.password))
        return super().authenticate_password(request)


class AlteredKeystone(TrackingKeystone):
    def __init__(self, accepted: SecretValue, alteration: str) -> None:
        super().__init__(accepted)
        self.alteration = alteration

    def authenticate_password(
        self, request: KeystonePasswordAuthRequest,
    ) -> KeystoneAuthenticationResult:
        if self.alteration == "first_indeterminate" and not self.auth_generations:
            self.auth_generations.append(CredentialGeneration.from_secret(request.password))
            return KeystoneAuthIndeterminate(KeystoneIndeterminateReason.DEPENDENCY_FAILURE)
        if self.alteration == "second_indeterminate" and len(self.auth_generations) == 1:
            self.auth_generations.append(CredentialGeneration.from_secret(request.password))
            return KeystoneAuthIndeterminate(KeystoneIndeterminateReason.DEPENDENCY_FAILURE)
        result = super().authenticate_password(request)
        if self.alteration == "rejected":
            return super(TrackingKeystone, self).authenticate_password(
                replace(request, password=A_UNKNOWN),
            )
        if self.alteration == "indeterminate":
            return KeystoneAuthIndeterminate(KeystoneIndeterminateReason.DEPENDENCY_FAILURE)
        if not isinstance(result, KeystoneAuthSuccess):
            return result
        observed = result.observation
        if self.alteration == "wrong_user":
            observed = replace(observed, user_id="wrong-user")
        elif self.alteration == "wrong_project":
            observed = replace(observed, project_id="wrong-project")
        elif self.alteration == "wrong_domain":
            observed = replace(observed, user_domain_id="wrong-domain")
        elif self.alteration == "wrong_role":
            observed = replace(observed, roles=())
        return replace(result, observation=observed)


class DualPasswordKeystone(TrackingKeystone):
    def __init__(self, old: SecretValue, new: SecretValue) -> None:
        super().__init__(new)
        self.old = old
        self.new = new

    def authenticate_password(
        self, request: KeystonePasswordAuthRequest,
    ) -> KeystoneAuthenticationResult:
        if request.password == self.old:
            return super().authenticate_password(
                replace(request, password=self.new),
            )
        return super().authenticate_password(request)
