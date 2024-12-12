control 'SV-214000' do
  title 'SQL Server must generate audit records when successful and unsuccessful attempts to add privileges/permissions occur.'
  desc 'Changes in the permissions, privileges, and roles granted to users and roles must be tracked. Without an audit trail, unauthorized elevation or restriction of privileges could go undetected. Elevated privileges give users access to information and functionality that they should not have; restricted privileges wrongly deny access to authorized users. 
 
In an SQL environment, adding permissions is typically done via the GRANT command, or, in the negative, the DENY command.  
 
To aid in diagnosis, it is necessary to keep track of failed attempts in addition to the successful ones.'
  desc 'check', "Check that SQL Server Audit is being used for the STIG compliant audit.

Determine if an audit is configured and started by executing the following query:

SELECT name AS 'Audit Name', 
status_desc AS 'Audit Status', 
audit_file_path AS 'Current Audit File' 
FROM sys.dm_server_audit_status

Execute the following query to verify the required audit actions are included in the server audit specification: 

SELECT a.name AS 'AuditName', 
s.name AS 'SpecName', 
d.audit_action_name AS 'ActionName', 
d.audited_result AS 'Result' 
FROM sys.server_audit_specifications s 
JOIN sys.server_audits a ON s.audit_guid = a.audit_guid 
JOIN sys.server_audit_specification_details d ON s.server_specification_id = d.server_specification_id 
WHERE a.is_state_enabled = 1
AND d.audit_action_name IN ('DATABASE_OBJECT_OWNERSHIP_CHANGE_GROUP'
,'DATABASE_OBJECT_PERMISSION_CHANGE_GROUP'
,'DATABASE_OWNERSHIP_CHANGE_GROUP'
,'DATABASE_PERMISSION_CHANGE_GROUP'
,'DATABASE_ROLE_MEMBER_CHANGE_GROUP'
,'SCHEMA_OBJECT_OWNERSHIP_CHANGE_GROUP'
,'SCHEMA_OBJECT_PERMISSION_CHANGE_GROUP'
,'SERVER_OBJECT_OWNERSHIP_CHANGE_GROUP'
,'SERVER_OBJECT_PERMISSION_CHANGE_GROUP'
,'SERVER_PERMISSION_CHANGE_GROUP'
,'SERVER_ROLE_MEMBER_CHANGE_GROUP')

If the any of the following audit actions are not returned in an active audit, this is a finding.

DATABASE_OBJECT_OWNERSHIP_CHANGE_GROUP 
DATABASE_OBJECT_PERMISSION_CHANGE_GROUP 
DATABASE_OWNERSHIP_CHANGE_GROUP 
DATABASE_PERMISSION_CHANGE_GROUP 
DATABASE_ROLE_MEMBER_CHANGE_GROUP 
SCHEMA_OBJECT_OWNERSHIP_CHANGE_GROUP 
SCHEMA_OBJECT_PERMISSION_CHANGE_GROUP 
SERVER_OBJECT_OWNERSHIP_CHANGE_GROUP 
SERVER_OBJECT_PERMISSION_CHANGE_GROUP 
SERVER_PERMISSION_CHANGE_GROUP 
SERVER_ROLE_MEMBER_CHANGE_GROUP 

If no records are returned, this is a finding."
  desc 'fix', 'Add the following events to the SQL Server Audit that is being used for the STIG compliant audit. 
 
DATABASE_OBJECT_OWNERSHIP_CHANGE_GROUP 
DATABASE_OBJECT_PERMISSION_CHANGE_GROUP 
DATABASE_OWNERSHIP_CHANGE_GROUP 
DATABASE_PERMISSION_CHANGE_GROUP 
DATABASE_ROLE_MEMBER_CHANGE_GROUP 
SCHEMA_OBJECT_OWNERSHIP_CHANGE_GROUP 
SCHEMA_OBJECT_PERMISSION_CHANGE_GROUP 
SERVER_OBJECT_OWNERSHIP_CHANGE_GROUP 
SERVER_OBJECT_PERMISSION_CHANGE_GROUP 
SERVER_PERMISSION_CHANGE_GROUP 
SERVER_ROLE_MEMBER_CHANGE_GROUP 
 
See the supplemental file "SQL 2016 Audit.sql". 

Reference: 
https://msdn.microsoft.com/en-us/library/cc280663.aspx'
  impact 0.5
  ref 'DPMS Target MS SQL Server 2016 Instance'
  tag check_id: 'C-15217r902990_chk'
  tag severity: 'medium'
  tag gid: 'V-214000'
  tag rid: 'SV-214000r902991_rule'
  tag stig_id: 'SQL6-D0-013400'
  tag gtitle: 'SRG-APP-000495-DB-000327'
  tag fix_id: 'F-15215r313784_fix'
  tag 'documentable'
  tag legacy: ['SV-82413', 'V-67923', 'SV-93967', 'V-79261']
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
  'DATABASE_OBJECT_OWNERSHIP_CHANGE_GROUP',
  'DATABASE_OBJECT_PERMISSION_CHANGE_GROUP',
  'DATABASE_OWNERSHIP_CHANGE_GROUP',
  'DATABASE_PERMISSION_CHANGE_GROUP',
  'DATABASE_ROLE_MEMBER_CHANGE_GROUP',
  'SCHEMA_OBJECT_OWNERSHIP_CHANGE_GROUP',
  'SCHEMA_OBJECT_PERMISSION_CHANGE_GROUP',
  'SERVER_OBJECT_OWNERSHIP_CHANGE_GROUP',
  'SERVER_OBJECT_PERMISSION_CHANGE_GROUP',
  'SERVER_PERMISSION_CHANGE_GROUP',
  'SERVER_ROLE_MEMBER_CHANGE_GROUP',
  'SCHEMA_OBJECT_ACCESS_GROUP'
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
          it { should include '42' }
          it { should include '43' }
          it { should include '90' }
          it { should include '102' }
          it { should include '103' }
          it { should include '104' }
          it { should include '105' }
          it { should include '108' }
          it { should include '109' }
          it { should include '110' }
          it { should include '111' }
          it { should include '162' }
          it { should include '170' }
          it { should include '171' }
          it { should include '172' }
          it { should include '173' }
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
