control 'SV-214016' do
  title 'SQL Server must generate audit records when unsuccessful attempts to execute privileged activities or other system-level access occur.'
  desc 'Without tracking privileged activity, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.  
 
System documentation should include a definition of the functionality considered privileged. 
 
A privileged function in this context is any operation that modifies the structure of the database, its built-in logic, or its security settings. This would include all Data Definition Language (DDL) statements and all security-related statements. In an SQL environment, it encompasses, but is not necessarily limited to: 
CREATE 
ALTER 
DROP 
GRANT 
REVOKE 
DENY 
 
Note that it is particularly important to audit, and tightly control, any action that weakens the implementation of this requirement itself, since the objective is to have a complete audit trail of all administrative activity. 
 
To aid in diagnosis, it is necessary to keep track of failed attempts in addition to the successful ones.'
  desc 'check', "Determine if an audit is configured and started by executing the following query.  

SELECT name AS 'Audit Name', 
status_desc AS 'Audit Status', 
audit_file_path AS 'Current Audit File' 
FROM sys.dm_server_audit_status 

If no records are returned, this is a finding. 

Execute the following query to verify the following events are included in the server audit specification: 

APPLICATION_ROLE_CHANGE_PASSWORD_GROUP 
AUDIT_CHANGE_GROUP 
BACKUP_RESTORE_GROUP 
DATABASE_CHANGE_GROUP 
DATABASE_OBJECT_CHANGE_GROUP 
DATABASE_OBJECT_OWNERSHIP_CHANGE_GROUP 
DATABASE_OBJECT_PERMISSION_CHANGE_GROUP 
DATABASE_OPERATION_GROUP 
DATABASE_OWNERSHIP_CHANGE_GROUP 
DATABASE_PERMISSION_CHANGE_GROUP 
DATABASE_PRINCIPAL_CHANGE_GROUP 
DATABASE_PRINCIPAL_IMPERSONATION_GROUP 
DATABASE_ROLE_MEMBER_CHANGE_GROUP 
DBCC_GROUP 
LOGIN_CHANGE_PASSWORD_GROUP
LOGOUT_GROUP 
SCHEMA_OBJECT_CHANGE_GROUP 
SCHEMA_OBJECT_OWNERSHIP_CHANGE_GROUP 
SCHEMA_OBJECT_PERMISSION_CHANGE_GROUP 
SERVER_OBJECT_CHANGE_GROUP 
SERVER_OBJECT_OWNERSHIP_CHANGE_GROUP 
SERVER_OBJECT_PERMISSION_CHANGE_GROUP 
SERVER_OPERATION_GROUP 
SERVER_PERMISSION_CHANGE_GROUP 
SERVER_PRINCIPAL_CHANGE_GROUP 
SERVER_PRINCIPAL_IMPERSONATION_GROUP 
SERVER_ROLE_MEMBER_CHANGE_GROUP 
SERVER_STATE_CHANGE_GROUP 
TRACE_CHANGE_GROUP 
USER_CHANGE_PASSWORD_GROUP 

SELECT a.name AS 'AuditName', 
s.name AS 'SpecName', 
d.audit_action_name AS 'ActionName', 
d.audited_result AS 'Result' 
FROM sys.server_audit_specifications s 
JOIN sys.server_audits a ON s.audit_guid = a.audit_guid 
JOIN sys.server_audit_specification_details d ON s.server_specification_id = d.server_specification_id 
WHERE a.is_state_enabled = 1  
AND d.audit_action_name IN ('APPLICATION_ROLE_CHANGE_PASSWORD_GROUP',
'AUDIT_CHANGE_GROUP',
'BACKUP_RESTORE_GROUP',
'DATABASE_CHANGE_GROUP',
'DATABASE_OBJECT_CHANGE_GROUP',
'DATABASE_OBJECT_OWNERSHIP_CHANGE_GROUP',
'DATABASE_OBJECT_PERMISSION_CHANGE_GROUP',
'DATABASE_OPERATION_GROUP',
'DATABASE_OWNERSHIP_CHANGE_GROUP',
'DATABASE_PERMISSION_CHANGE_GROUP',
'DATABASE_PRINCIPAL_CHANGE_GROUP',
'DATABASE_PRINCIPAL_IMPERSONATION_GROUP',
'DATABASE_ROLE_MEMBER_CHANGE_GROUP',
'DBCC_GROUP',
'LOGIN_CHANGE_PASSWORD_GROUP',
'LOGOUT_GROUP',
'SCHEMA_OBJECT_CHANGE_GROUP',
'SCHEMA_OBJECT_OWNERSHIP_CHANGE_GROUP',
'SCHEMA_OBJECT_PERMISSION_CHANGE_GROUP',
'SERVER_OBJECT_CHANGE_GROUP',
'SERVER_OBJECT_OWNERSHIP_CHANGE_GROUP',
'SERVER_OBJECT_PERMISSION_CHANGE_GROUP',
'SERVER_OPERATION_GROUP',
'SERVER_PERMISSION_CHANGE_GROUP',
'SERVER_PRINCIPAL_CHANGE_GROUP',
'SERVER_PRINCIPAL_IMPERSONATION_GROUP',
'SERVER_ROLE_MEMBER_CHANGE_GROUP',
'SERVER_STATE_CHANGE_GROUP',
'TRACE_CHANGE_GROUP',
'USER_CHANGE_PASSWORD_GROUP'
)
Order by d.audit_action_name


If the identified groups are not returned, this is a finding."
  desc 'fix', 'Add the required events to the server audit specification 
USE [master]; 
GO  

ALTER SERVER AUDIT SPECIFICATION STIG_AUDIT_SERVER_SPECIFICATION WITH (STATE = OFF);  
GO  

ALTER SERVER AUDIT SPECIFICATION STIG_AUDIT_SERVER_SPECIFICATION ADD (APPLICATION_ROLE_CHANGE_PASSWORD_GROUP); 
ALTER SERVER AUDIT SPECIFICATION STIG_AUDIT_SERVER_SPECIFICATION ADD (AUDIT_CHANGE_GROUP); 
ALTER SERVER AUDIT SPECIFICATION STIG_AUDIT_SERVER_SPECIFICATION ADD (BACKUP_RESTORE_GROUP); 
ALTER SERVER AUDIT SPECIFICATION STIG_AUDIT_SERVER_SPECIFICATION ADD (DATABASE_CHANGE_GROUP); 
ALTER SERVER AUDIT SPECIFICATION STIG_AUDIT_SERVER_SPECIFICATION ADD (DATABASE_OBJECT_CHANGE_GROUP); 
ALTER SERVER AUDIT SPECIFICATION STIG_AUDIT_SERVER_SPECIFICATION ADD (DATABASE_OBJECT_OWNERSHIP_CHANGE_GROUP); 
ALTER SERVER AUDIT SPECIFICATION STIG_AUDIT_SERVER_SPECIFICATION ADD (DATABASE_OBJECT_PERMISSION_CHANGE_GROUP); 
ALTER SERVER AUDIT SPECIFICATION STIG_AUDIT_SERVER_SPECIFICATION ADD (DATABASE_OPERATION_GROUP); 
ALTER SERVER AUDIT SPECIFICATION STIG_AUDIT_SERVER_SPECIFICATION ADD (DATABASE_OWNERSHIP_CHANGE_GROUP); 
ALTER SERVER AUDIT SPECIFICATION STIG_AUDIT_SERVER_SPECIFICATION ADD (DATABASE_PERMISSION_CHANGE_GROUP); 
ALTER SERVER AUDIT SPECIFICATION STIG_AUDIT_SERVER_SPECIFICATION ADD (DATABASE_PRINCIPAL_CHANGE_GROUP); 
ALTER SERVER AUDIT SPECIFICATION STIG_AUDIT_SERVER_SPECIFICATION ADD (DATABASE_PRINCIPAL_IMPERSONATION_GROUP); 
ALTER SERVER AUDIT SPECIFICATION STIG_AUDIT_SERVER_SPECIFICATION ADD (DATABASE_ROLE_MEMBER_CHANGE_GROUP); 
ALTER SERVER AUDIT SPECIFICATION STIG_AUDIT_SERVER_SPECIFICATION ADD (DBCC_GROUP); 
ALTER SERVER AUDIT SPECIFICATION STIG_AUDIT_SERVER_SPECIFICATION ADD (LOGIN_CHANGE_PASSWORD_GROUP); 
ALTER SERVER AUDIT SPECIFICATION STIG_AUDIT_SERVER_SPECIFICATION ADD (LOGOUT_GROUP); 
ALTER SERVER AUDIT SPECIFICATION STIG_AUDIT_SERVER_SPECIFICATION ADD (SCHEMA_OBJECT_CHANGE_GROUP); 
ALTER SERVER AUDIT SPECIFICATION STIG_AUDIT_SERVER_SPECIFICATION ADD (SCHEMA_OBJECT_OWNERSHIP_CHANGE_GROUP); 
ALTER SERVER AUDIT SPECIFICATION STIG_AUDIT_SERVER_SPECIFICATION ADD (SCHEMA_OBJECT_PERMISSION_CHANGE_GROUP); 
ALTER SERVER AUDIT SPECIFICATION STIG_AUDIT_SERVER_SPECIFICATION ADD (SERVER_OBJECT_CHANGE_GROUP); 
ALTER SERVER AUDIT SPECIFICATION STIG_AUDIT_SERVER_SPECIFICATION ADD (SERVER_OBJECT_OWNERSHIP_CHANGE_GROUP); 
ALTER SERVER AUDIT SPECIFICATION STIG_AUDIT_SERVER_SPECIFICATION ADD (SERVER_OBJECT_PERMISSION_CHANGE_GROUP); 
ALTER SERVER AUDIT SPECIFICATION STIG_AUDIT_SERVER_SPECIFICATION ADD (SERVER_OPERATION_GROUP); 
ALTER SERVER AUDIT SPECIFICATION STIG_AUDIT_SERVER_SPECIFICATION ADD (SERVER_PERMISSION_CHANGE_GROUP); 
ALTER SERVER AUDIT SPECIFICATION STIG_AUDIT_SERVER_SPECIFICATION ADD (SERVER_PRINCIPAL_CHANGE_GROUP); 
ALTER SERVER AUDIT SPECIFICATION STIG_AUDIT_SERVER_SPECIFICATION ADD (SERVER_PRINCIPAL_IMPERSONATION_GROUP); 
ALTER SERVER AUDIT SPECIFICATION STIG_AUDIT_SERVER_SPECIFICATION ADD (SERVER_ROLE_MEMBER_CHANGE_GROUP); 
ALTER SERVER AUDIT SPECIFICATION STIG_AUDIT_SERVER_SPECIFICATION ADD (SERVER_STATE_CHANGE_GROUP); 
ALTER SERVER AUDIT SPECIFICATION STIG_AUDIT_SERVER_SPECIFICATION ADD (TRACE_CHANGE_GROUP); 
ALTER SERVER AUDIT SPECIFICATION STIG_AUDIT_SERVER_SPECIFICATION ADD (USER_CHANGE_PASSWORD_GROUP); 
GO 

ALTER SERVER AUDIT SPECIFICATION STIG_AUDIT_SERVER_SPECIFICATION WITH (STATE = ON);  
GO'
  impact 0.5
  ref 'DPMS Target MS SQL Server 2016 Instance'
  tag check_id: 'C-15233r313831_chk'
  tag severity: 'medium'
  tag gid: 'V-214016'
  tag rid: 'SV-214016r879875_rule'
  tag stig_id: 'SQL6-D0-015000'
  tag gtitle: 'SRG-APP-000504-DB-000355'
  tag fix_id: 'F-15231r313832_fix'
  tag 'documentable'
  tag legacy: ['SV-82425', 'V-67935', 'SV-93999', 'V-79293']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']

  server_trace_implemented = input('server_trace_implemented')
  server_audit_implemented = input('server_audit_implemented')

  sql_session = mssql_session(user: input('user'),
                              password: input('password'),
                              host: input('host'),
                              instance: input('instance'),
                              port: input('port'),
                              db_name: input('db_name'))

  query_traces = %(
    SELECT * FROM sys.traces
  )
  query_trace_eventinfo = %(
    SELECT DISTINCT(eventid) FROM sys.fn_trace_geteventinfo(%<trace_id>s);
  )

  query_audits = %(
    SELECT audited_result FROM sys.server_audit_specification_details WHERE audit_action_name IN
  (
  'APPLICATION_ROLE_CHANGE_PASSWORD_GROUP',
  'AUDIT_CHANGE_GROUP',
  'BACKUP_RESTORE_GROUP',
  'DATABASE_CHANGE_GROUP',
  'DATABASE_OBJECT_ACCESS_GROUP',
  'DATABASE_OBJECT_OWNERSHIP_CHANGE_GROUP',
  'DATABASE_OBJECT_PERMISSION_CHANGE_GROUP',
  'DATABASE_OPERATION_GROUP',
  'DATABASE_OWNERSHIP_CHANGE_GROUP',
  'DATABASE_PERMISSION_CHANGE_GROUP',
  'DATABASE_PRINCIPAL_CHANGE_GROUP',
  'DATABASE_PRINCIPAL_IMPERSONATION_GROUP',
  'DATABASE_ROLE_MEMBER_CHANGE_GROUP',
  'DBCC_GROUP',
  'FAILED_LOGIN_GROUP',
  'LOGIN_CHANGE_PASSWORD_GROUP',
  'LOGOUT_GROUP',
  'SCHEMA_OBJECT_ACCESS_GROUP',
  'SCHEMA_OBJECT_CHANGE_GROUP',
  'SCHEMA_OBJECT_OWNERSHIP_CHANGE_GROUP',
  'SCHEMA_OBJECT_PERMISSION_CHANGE_GROUP',
  'SERVER_OBJECT_CHANGE_GROUP',
  'SERVER_OBJECT_OWNERSHIP_CHANGE_GROUP',
  'SERVER_OBJECT_PERMISSION_CHANGE_GROUP',
  'SERVER_OPERATION_GROUP',
  'SERVER_PERMISSION_CHANGE_GROUP',
  'SERVER_PRINCIPAL_CHANGE_GROUP',
  'SERVER_PRINCIPAL_IMPERSONATION_GROUP',
  'SERVER_ROLE_MEMBER_CHANGE_GROUP',
  'SERVER_STATE_CHANGE_GROUP',
  'SUCCESSFUL_LOGIN_GROUP',
  'TRACE_CHANGE_GROUP'
  );

  )

  describe.one do
    describe 'SQL Server Trace is in use for audit purposes' do
      subject { server_trace_implemented }
      it { should be true }
    end

    describe 'SQL Server Audit is in use for audit purposes' do
      subject { server_audit_implemented }
      it { should be true }
    end
  end

  query_traces = %(
    SELECT * FROM sys.traces
  )

  if server_trace_implemented
    describe 'List defined traces for the SQL server instance' do
      subject { sql_session.query(query_traces) }
      it { should_not be_empty }
    end

    trace_ids = sql_session.query(query_traces).column('id')
    describe.one do
      trace_ids.each do |trace_id|
        found_events = sql_session.query(format(query_trace_eventinfo, trace_id: trace_id)).column('eventid')
        describe "EventsIDs in Trace ID:#{trace_id}" do
          subject { found_events }
          it { should include '46' }
          it { should include '47' }
          it { should include '90' }
          it { should include '115' }
          it { should include '116' }
          it { should include '117' }
          it { should include '118' }
          it { should include '128' }
          it { should include '129' }
          it { should include '130' }
          it { should include '131' }
          it { should include '164' }
          it { should include '170' }
          it { should include '171' }
          it { should include '172' }
          it { should include '173' }
          it { should include '175' }
          it { should include '176' }
          it { should include '177' }
        end
      end
    end
  end

  if server_audit_implemented
    describe 'SQL Server Audit:' do
      describe 'Defined Audits with Audit Action SCHEMA_OBJECT_ACCESS_GROUP' do
        subject { sql_session.query(query_audits) }
        it { should_not be_empty }
      end
      describe 'Audited Result for Defined Audit Actions' do
        subject { sql_session.query(query_audits).column('audited_result').uniq.to_s }
        it { should match(/SUCCESS AND FAILURE|FAILURE/) }
      end
    end
  end
end
