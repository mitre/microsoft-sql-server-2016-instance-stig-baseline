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
  tag check_id: 'C-15233r313831_chk'
  tag severity: 'medium'
  tag gid: 'V-214016'
  tag rid: 'SV-214016r879875_rule'
  tag stig_id: 'SQL6-D0-015000'
  tag gtitle: 'SRG-APP-000504-DB-000355'
  tag fix_id: 'F-15231r313832_fix'
  tag 'documentable'
  tag legacy: ['SV-93999', 'V-79293']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end