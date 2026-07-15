-- Supabase function hardening for linter warnings:
-- - function_search_path_mutable
-- - anon_security_definer_function_executable
-- - authenticated_security_definer_function_executable
--
-- Run this in Supabase SQL Editor against the target database.

begin;

-- 1) Pin a safe search_path for all user-defined functions in public schema.
--    This removes role-mutable search_path warnings.
do $$
declare
  fn regprocedure;
begin
  for fn in
    select p.oid::regprocedure
    from pg_proc p
    join pg_namespace n on n.oid = p.pronamespace
    where n.nspname = 'public'
      and p.prokind = 'f'
  loop
    execute format(
      'alter function %s set search_path = public, pg_temp',
      fn
    );
  end loop;
end
$$;

-- 2) Reduce SECURITY DEFINER exposure by removing RPC execution from
--    externally reachable roles (anon + authenticated) in public schema.
--    service_role keeps execute access for trusted server-side operations.
do $$
declare
  fn regprocedure;
begin
  for fn in
    select p.oid::regprocedure
    from pg_proc p
    join pg_namespace n on n.oid = p.pronamespace
    where n.nspname = 'public'
      and p.prokind = 'f'
      and p.prosecdef
  loop
    execute format('revoke execute on function %s from anon', fn);
    execute format('revoke execute on function %s from authenticated', fn);
    execute format('grant execute on function %s to service_role', fn);
  end loop;
end
$$;

commit;
