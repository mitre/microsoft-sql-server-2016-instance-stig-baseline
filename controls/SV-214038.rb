control 'SV-214038' do
  title 'Hadoop Connectivity feature must be disabled, unless specifically required and approved.'
  desc 'Information systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions). 

It is detrimental for applications to provide, or install by default, functionality exceeding requirements or mission objectives. 

Applications must adhere to the principles of least functionality by providing only essential capabilities.

SQL Server may spawn additional external processes to execute procedures that are defined in the SQL Server but stored in external host files (external procedures). The spawned process used to execute the external procedure may operate within a different OS security context than SQL Server and provide unauthorized access to the host system.

SQL Server is capable of providing a wide range of features and services. Some of the features and services, provided by default, may not be necessary, and enabling them could adversely affect the security of the system.

The Hadoop Connectivity feature allows multiple types of external data sources to be created and used across all sessions on the server.  An exploit to the SQL Server instance could result in a compromise of the host system and external SQL Server resources.'
  desc 'check', %q(To determine if "Hadoop Connectivity" option is enabled, execute the following query: 

EXEC SP_CONFIGURE 'show advanced options', '1'; 
RECONFIGURE WITH OVERRIDE; 
EXEC SP_CONFIGURE 'hadoop connectivity'; 

If the value of "config_value" is "0", this is not a finding.

If the value of "config_value" is "1", review the system documentation to determine whether the use of "Hadoop Connectivity" option is required and authorized. If it is not authorized, this is a finding.)
  desc 'fix', %q(Disable use of or remove any external application executable object definitions that are not authorized. To disable the use of "Hadoop Connectivity" option, from the query prompt: 

sp_configure 'show advanced options', 1;  
GO  
RECONFIGURE;  
GO  
sp_configure 'hadoop connectivity', 0;  
GO  
RECONFIGURE;  
GO)
  impact 0.5
  tag check_id: 'C-15255r313897_chk'
  tag severity: 'medium'
  tag gid: 'V-214038'
  tag rid: 'SV-214038r879587_rule'
  tag stig_id: 'SQL6-D0-017400'
  tag gtitle: 'SRG-APP-000141-DB-000093'
  tag fix_id: 'F-15253r313898_fix'
  tag 'documentable'
  tag legacy: ['SV-94047', 'V-79341']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end