control 'SV-214018' do
  title 'SQL Server must generate audit records when concurrent logons/connections by the same user from different workstations occur.'
  desc 'For completeness of forensic analysis, it is necessary to track who logs on to SQL Server. 
 
Concurrent connections by the same user from multiple workstations may be valid use of the system; or such connections may be due to improper circumvention of the requirement to use the CAC for authentication; or they may indicate unauthorized account sharing; or they may be because an account has been compromised. 
 
(If the fact of multiple, concurrent logons by a given user can be reliably reconstructed from the log entries for other events (logons/connections; voluntary and involuntary disconnections), then it is not mandatory to create additional log entries specifically for this.)'
  desc 'check', %q(Determine if an audit is configured and started by executing the following query. 
 
SELECT name AS 'Audit Name', 
  status_desc AS 'Audit Status', 
  audit_file_path AS 'Current Audit File' 
FROM sys.dm_server_audit_status 
 
If no records are returned, this is a finding. 
 
Execute the following query to verify the "SUCCESSFUL_LOGIN_GROUP" is included in the server audit specification. 
 
SELECT a.name AS 'AuditName', 
s.name AS 'SpecName', 
d.audit_action_name AS 'ActionName', 
d.audited_result AS 'Result' 
FROM sys.server_audit_specifications s 
JOIN sys.server_audits a ON s.audit_guid = a.audit_guid 
JOIN sys.server_audit_specification_details d ON s.server_specification_id = d.server_specification_id 
WHERE a.is_state_enabled = 1 AND d.audit_action_name = 'SUCCESSFUL_LOGIN_GROUP' 
 
If the "SUCCESSFUL_LOGIN_GROUP" is returned in an active audit, this is not a finding. 
 
If "SUCCESSFUL_LOGIN_GROUP" is not in the active audit, determine whether "Both failed and successful logins" is enabled. 
 
In SQL Management Studio: 
Right-click on the instance >> Select "Properties" >> Select "Security" on the left hand side >> Check the setting for "Login auditing" 
 
If "Both failed and successful logins" is not selected, this is a finding.)
  desc 'fix', 'Add the "SUCCESSFUL_LOGIN_GROUP" to the server audit specification. 
USE [master]; 
GO  
 
ALTER SERVER AUDIT SPECIFICATION STIG_AUDIT_SERVER_SPECIFICATION WITH (STATE = OFF);  
GO  
 
ALTER SERVER AUDIT SPECIFICATION STIG_AUDIT_SERVER_SPECIFICATION ADD (SUCCESSFUL_LOGIN_GROUP);  
GO  
 
ALTER SERVER AUDIT SPECIFICATION STIG_AUDIT_SERVER_SPECIFICATION WITH (STATE = ON);  
GO 
 
Alternatively, enable "Both failed and successful logins" 
In SQL Management Studio: 
Right-click on the instance >> Select "Properties" >> Select "Security" on the left hand side >> Select "Both failed and successful logins" >> Click "OK"'
  impact 0.5
  ref 'DPMS Target MS SQL Server 2016 Instance'
  tag check_id: 'C-15235r313837_chk'
  tag severity: 'medium'
  tag gid: 'V-214018'
  tag rid: 'SV-214018r879877_rule'
  tag stig_id: 'SQL6-D0-015200'
  tag gtitle: 'SRG-APP-000506-DB-000353'
  tag fix_id: 'F-15233r313838_fix'
  tag 'documentable'
  tag legacy: ['SV-82429', 'V-67939', 'SV-94003', 'V-79297']
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

  query_audits_logout_group = %(
    SELECT audited_result FROM sys.server_audit_specification_details WHERE audit_action_name = 'LOGOUT_GROUP'
  )

  query_audits_successful_login_group = %(
    SELECT audited_result FROM sys.server_audit_specification_details WHERE audit_action_name = 'SUCCESSFUL_LOGIN_GROUP'
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
          it { should include '14' }
          it { should include '15' }
          it { should include '16' }
          it { should include '17' }
        end
      end
    end
  end

  if server_audit_implemented
    describe 'SQL Server Audit:' do
      describe 'Defined Audits with Audit name LOGOUT_GROUP' do
        subject { sql_session.query(query_audits_logout_group) }
        it { should_not be_empty }
      end
      describe 'Defined Audits with Audit name SUCCESSFUL_LOGIN_GROUP' do
        subject { sql_session.query(query_audits_successful_login_group) }
        it { should_not be_empty }
      end
    end
  end
end
