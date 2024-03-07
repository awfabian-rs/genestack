# SSH to utility server for ENVIRONMENT.

@_get_utility_server ENVIRONMENT:
  case {{ ENVIRONMENT }} in \
  sjc|sjc3) \
  echo -n "66.70.54.104"
