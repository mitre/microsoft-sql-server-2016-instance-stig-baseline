control 'SV-213989' do
  title 'SQL Server must produce audit records of its enforcement of access restrictions associated with changes to the configuration of SQL Server or database(s).'
  desc 'Without auditing the enforcement of access restrictions against changes to configuration, it would be difficult to identify attempted attacks and an audit trail would not be available for forensic investigation for after-the-fact actions.  
 
Enforcement actions are the methods or mechanisms used to prevent unauthorized changes to configuration settings. Enforcement action methods may be as simple as denying access to a file based on the application of file permissions (access restriction). Audit items may consist of lists of actions blocked by access restrictions or changes identified after the fact.'
  desc 'check', "Determine if an audit is configured to capture denied actions and started by executing the following query:

SELECT name AS 'Audit Name',
status_desc AS 'Audit Status',
audit_file_path AS 'Current Audit File'
FROM sys.dm_server_audit_status

If no records are returned, this is a finding.

Execute the following query to verify the following events are included in the server audit specification:

APPLICATION_ROLE_CHANGE_PASSWORD_GROUP,
AUDIT_CHANGE_GROUP,
BACKUP_RESTORE_GROUP,
DATABASE_CHANGE_GROUP,
DATABASE_OBJECT_ACCESS_GROUP,
DATABASE_OBJECT_CHANGE_GROUP,
DATABASE_OBJECT_OWNERSHIP_CHANGE_GROUP,
DATABASE_OBJECT_PERMISSION_CHANGE_GROUP,
DATABASE_OWNERSHIP_CHANGE_GROUP,
DATABASE_OPERATION_GROUP,
DATABASE_PERMISSION_CHANGE_GROUP,
DATABASE_PRINCIPAL_CHANGE_GROUP,
DATABASE_PRINCIPAL_IMPERSONATION_GROUP,
DATABASE_ROLE_MEMBER_CHANGE_GROUP,
DBCC_GROUP,
LOGIN_CHANGE_PASSWORD_GROUP,
SCHEMA_OBJECT_CHANGE_GROUP,
SCHEMA_OBJECT_OWNERSHIP_CHANGE_GROUP,
SCHEMA_OBJECT_PERMISSION_CHANGE_GROUP,
SERVER_OBJECT_CHANGE_GROUP,
SERVER_OBJECT_OWNERSHIP_CHANGE_GROUP,
SERVER_OBJECT_PERMISSION_CHANGE_GROUP,
SERVER_OPERATION_GROUP,
SERVER_PERMISSION_CHANGE_GROUP,
SERVER_PRINCIPAL_IMPERSONATION_GROUP,
SERVER_ROLE_MEMBER_CHANGE_GROUP,
SERVER_STATE_CHANGE_GROUP,
TRACE_CHANGE_GROUP

SELECT a.name AS 'AuditName',
s.name AS 'SpecName',
d.audit_action_name AS 'ActionName',
d.audited_result AS 'Result'
FROM sys.server_audit_specifications s
JOIN sys.server_audits a ON s.audit_guid = a.audit_guid
JOIN sys.server_audit_specification_details d ON s.server_specification_id = d.server_specification_id
WHERE a.is_state_enabled = 1
AND d.audit_action_name IN (
'APPLICATION_ROLE_CHANGE_PASSWORD_GROUP',
'AUDIT_CHANGE_GROUP',
'BACKUP_RESTORE_GROUP',
'DATABASE_CHANGE_GROUP',
'DATABASE_OBJECT_ACCESS_GROUP',
'DATABASE_OBJECT_CHANGE_GROUP',
'DATABASE_OBJECT_OWNERSHIP_CHANGE_GROUP',
'DATABASE_OBJECT_PERMISSION_CHANGE_GROUP',
'DATABASE_OWNERSHIP_CHANGE_GROUP',
'DATABASE_OPERATION_GROUP',
'DATABASE_PERMISSION_CHANGE_GROUP',
'DATABASE_PRINCIPAL_CHANGE_GROUP',
'DATABASE_PRINCIPAL_IMPERSONATION_GROUP',
'DATABASE_ROLE_MEMBER_CHANGE_GROUP', 
'DBCC_GROUP',
'LOGIN_CHANGE_PASSWORD_GROUP',
'SCHEMA_OBJECT_CHANGE_GROUP',
'SCHEMA_OBJECT_OWNERSHIP_CHANGE_GROUP',
'SCHEMA_OBJECT_PERMISSION_CHANGE_GROUP',
'SERVER_OBJECT_CHANGE_GROUP',
'SERVER_OBJECT_OWNERSHIP_CHANGE_GROUP',
'SERVER_OBJECT_PERMISSION_CHANGE_GROUP',
'SERVER_OPERATION_GROUP',
'SERVER_PERMISSION_CHANGE_GROUP',
'SERVER_PRINCIPAL_IMPERSONATION_GROUP',
'SERVER_ROLE_MEMBER_CHANGE_GROUP',
'SERVER_STATE_CHANGE_GROUP',
'TRACE_CHANGE_GROUP'
)
Order by d.audit_action_name

If the identified groups are not returned, this is a finding."
  desc 'fix', 'Add the required events to the server audit specification to audit denied actions. 
USE [master]; 
GO  

ALTER SERVER AUDIT SPECIFICATION STIG_AUDIT_SERVER_SPECIFICATION WITH (STATE = OFF);  
GO  

ALTER SERVER AUDIT SPECIFICATION STIG_AUDIT_SERVER_SPECIFICATION ADD (APPLICATION_ROLE_CHANGE_PASSWORD_GROUP ); 
ALTER SERVER AUDIT SPECIFICATION STIG_AUDIT_SERVER_SPECIFICATION ADD (AUDIT_CHANGE_GROUP ); 
ALTER SERVER AUDIT SPECIFICATION STIG_AUDIT_SERVER_SPECIFICATION ADD (BACKUP_RESTORE_GROUP ); 
ALTER SERVER AUDIT SPECIFICATION STIG_AUDIT_SERVER_SPECIFICATION ADD (DATABASE_CHANGE_GROUP ); 
ALTER SERVER AUDIT SPECIFICATION STIG_AUDIT_SERVER_SPECIFICATION ADD (DATABASE_OBJECT_ACCESS_GROUP ); 
ALTER SERVER AUDIT SPECIFICATION STIG_AUDIT_SERVER_SPECIFICATION ADD (DATABASE_OBJECT_CHANGE_GROUP ); 
ALTER SERVER AUDIT SPECIFICATION STIG_AUDIT_SERVER_SPECIFICATION ADD (DATABASE_OBJECT_OWNERSHIP_CHANGE_GROUP ); 
ALTER SERVER AUDIT SPECIFICATION STIG_AUDIT_SERVER_SPECIFICATION ADD (DATABASE_OBJECT_PERMISSION_CHANGE_GROUP ); 
ALTER SERVER AUDIT SPECIFICATION STIG_AUDIT_SERVER_SPECIFICATION ADD (DATABASE_OWNERSHIP_CHANGE_GROUP ); 
ALTER SERVER AUDIT SPECIFICATION STIG_AUDIT_SERVER_SPECIFICATION ADD (DATABASE_OPERATION_GROUP ); 
ALTER SERVER AUDIT SPECIFICATION STIG_AUDIT_SERVER_SPECIFICATION ADD (DATABASE_PERMISSION_CHANGE_GROUP ); 
ALTER SERVER AUDIT SPECIFICATION STIG_AUDIT_SERVER_SPECIFICATION ADD (DATABASE_PRINCIPAL_CHANGE_GROUP ); 
ALTER SERVER AUDIT SPECIFICATION STIG_AUDIT_SERVER_SPECIFICATION ADD (DATABASE_PRINCIPAL_IMPERSONATION_GROUP ); 
ALTER SERVER AUDIT SPECIFICATION STIG_AUDIT_SERVER_SPECIFICATION ADD (DATABASE_ROLE_MEMBER_CHANGE_GROUP ); 
ALTER SERVER AUDIT SPECIFICATION STIG_AUDIT_SERVER_SPECIFICATION ADD 
(DBCC_GROUP ); 
ALTER SERVER AUDIT SPECIFICATION STIG_AUDIT_SERVER_SPECIFICATION ADD (LOGIN_CHANGE_PASSWORD_GROUP ); 
ALTER SERVER AUDIT SPECIFICATION STIG_AUDIT_SERVER_SPECIFICATION ADD (SCHEMA_OBJECT_CHANGE_GROUP ); 
ALTER SERVER AUDIT SPECIFICATION STIG_AUDIT_SERVER_SPECIFICATION ADD (SCHEMA_OBJECT_OWNERSHIP_CHANGE_GROUP ); 
ALTER SERVER AUDIT SPECIFICATION STIG_AUDIT_SERVER_SPECIFICATION ADD (SCHEMA_OBJECT_PERMISSION_CHANGE_GROUP ); 
ALTER SERVER AUDIT SPECIFICATION STIG_AUDIT_SERVER_SPECIFICATION ADD (SERVER_OBJECT_CHANGE_GROUP ); 
ALTER SERVER AUDIT SPECIFICATION STIG_AUDIT_SERVER_SPECIFICATION ADD (SERVER_OBJECT_OWNERSHIP_CHANGE_GROUP ); 
ALTER SERVER AUDIT SPECIFICATION STIG_AUDIT_SERVER_SPECIFICATION ADD (SERVER_OBJECT_PERMISSION_CHANGE_GROUP ); 
ALTER SERVER AUDIT SPECIFICATION STIG_AUDIT_SERVER_SPECIFICATION ADD (SERVER_OPERATION_GROUP ); 
ALTER SERVER AUDIT SPECIFICATION STIG_AUDIT_SERVER_SPECIFICATION ADD (SERVER_PERMISSION_CHANGE_GROUP ); 
ALTER SERVER AUDIT SPECIFICATION STIG_AUDIT_SERVER_SPECIFICATION ADD (SERVER_PRINCIPAL_IMPERSONATION_GROUP ); 
ALTER SERVER AUDIT SPECIFICATION STIG_AUDIT_SERVER_SPECIFICATION ADD (SERVER_ROLE_MEMBER_CHANGE_GROUP ); 
ALTER SERVER AUDIT SPECIFICATION STIG_AUDIT_SERVER_SPECIFICATION ADD (SERVER_STATE_CHANGE_GROUP ); 
ALTER SERVER AUDIT SPECIFICATION STIG_AUDIT_SERVER_SPECIFICATION ADD (TRACE_CHANGE_GROUP ); 
GO 

ALTER SERVER AUDIT SPECIFICATION STIG_AUDIT_SERVER_SPECIFICATION WITH (STATE = ON);  
GO'
  impact 0.5
  tag check_id: 'C-15206r754635_chk'
  tag severity: 'medium'
  tag gid: 'V-213989'
  tag rid: 'SV-213989r879754_rule'
  tag stig_id: 'SQL6-D0-011800'
  tag gtitle: 'SRG-APP-000381-DB-000361'
  tag fix_id: 'F-15204r313751_fix'
  tag 'documentable'
  tag legacy: ['SV-93945', 'V-79239']
  tag cci: ['CCI-001814']
  tag nist: ['CM-5 (1)']
end
