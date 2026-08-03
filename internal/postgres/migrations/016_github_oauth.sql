alter table auth_login_flows drop constraint auth_login_flows_provider_check;
alter table auth_login_flows
    add constraint auth_login_flows_provider_check
    check (provider in ('oidc','github'));

alter table auth_sessions drop constraint auth_sessions_provider_check;
alter table auth_sessions
    add constraint auth_sessions_provider_check
    check (provider in ('oidc','oauth','local'));
