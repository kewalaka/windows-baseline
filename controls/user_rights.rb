
title 'User Rights Assignment'

isdomaincontroller = attribute('isdomaincontroller', default: false, description: 'Should we apply controls for domain controllers')

control 'cis-access-cred-manager-2.2.1' do
  impact 0.7
  title '2.2.1 Set Access Credential Manager as a trusted caller to No One'
  desc 'Set Access Credential Manager as a trusted caller to No One'
  tag cis: ['windows_2012r2:2.2.1', 'windows_2016:2.2.1', 'level1']
  ref 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0'
  ref 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.0.0'
  describe security_policy do
    its('SeTrustedCredManAccessPrivilege') { should eq ['S-1-0-0'] }
  end
end

control 'cis-network-access-2.2.2' do
  impact 0.7
  title '2.2.2 Set Access this computer from the network'
  desc 'Set Access this computer from the network'
  tag cis: ['windows_2012r2:2.2.2', 'windows_2016:2.2.2', 'level1']
  ref 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0'
  ref 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.0.0'
  describe security_policy do
    its('SeNetworkLogonRight') { should eq ['S-1-0-0'] }
  end
end

control 'cis-act-as-os-2.2.3' do
  impact 0.7
  title '2.2.3 Set Act as part of the operating system to No One'
  desc 'Set Act as part of the operating system to No One'
  tag cis: ['windows_2012r2:2.2.3', 'windows_2016:2.2.3', 'level1']
  ref 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0'
  ref 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.0.0'
  describe security_policy do
    its('SeTcbPrivilege') { should eq ['S-1-0-0'] }
  end
end

control 'cis-add-workstations-2.2.4' do
  impact 0.7
  title '2.2.4 Set Add workstations to domain to Administrators'
  desc 'Set Add workstations to domain to Administrators'
  tag cis: ['windows_2012r2:2.2.4', 'windows_2016:2.2.4', 'level1']
  ref 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0'
  ref 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.0.0'
  describe security_policy do
    its('SeMachineAccountPrivilege') { should eq ['S-1-5-32-544'] }
  end
end

control 'cis-adjust-memory-quotas-2.2.5' do
  impact 0.7
  title '2.2.5 Set Adust memory quotas for a process to Administrators, LOCAL SERVICE, NETWORK SERVICE'
  desc 'Set Adust memory quotas for a process to Administrators, LOCAL SERVICE, NETWORK SERVICE'
  tag cis: ['windows_2012r2:2.2.5', 'windows_2016:2.2.5', 'level1']
  ref 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0'
  ref 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.0.0'
  describe security_policy do
    its('SeIncreaseQuotaPrivilege') { should include 'S-1-5-19' }
    its('SeIncreaseQuotaPrivilege') { should include 'S-1-5-20' }
    its('SeIncreaseQuotaPrivilege') { should include 'S-1-5-32-544' }
  end
end

control 'cis-allow-logon-locally-2.2.6' do
  impact 0.7
  title '2.2.6 Set Allow logon locally to Administrators & Enterprise Domain Controllers for domain controllers'
  tag cis: ['windows_2012r2:2.2.6', 'windows_2016:2.2.6', 'level1']
  ref 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0'
  ref 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.0.0'
  if isdomaincontroller
    describe security_policy do
      its('SeInteractiveLogonRight') { should eq ['S-1-5-32-544','S-1-5-9'] } 
    end
  else
    describe security_policy do
      its('SeInteractiveLogonRight') { should eq ['S-1-5-32-544'] }
    end
  end
end

control 'cis-allow-logon-through-RDS-2.2.7' do
  impact 0.7
  title '2.2.7 Set log on through Remote Desktop Services'
  desc 'The following may optionally be able to log in use RDS - Administrators (DCs and member servers), and Remote Desktop Users (member servers)'
  tag cis: ['windows_2012r2:2.2.7', 'windows_2016:2.2.7', 'level1']
  ref 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0'
  ref 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.0.0'
  if isdomaincontroller    
    describe.one do
      describe security_policy do
        its('SeRemoteInteractiveLogonRight') { should eq ['S-1-5-32-544'] } 
      end
      describe security_policy do
        its('SeRemoteInteractiveLogonRight') { should eq [''] } 
      end
    end
  else
    describe.one do    
      describe security_policy do
        its('SeRemoteInteractiveLogonRight') { should eq ['S-1-5-32-544', 'S-1-5-32-555'] } 
      end
      describe security_policy do
        its('SeRemoteInteractiveLogonRight') { should eq ['S-1-5-32-544'] } 
      end
      describe security_policy do
        its('SeRemoteInteractiveLogonRight') { should eq [''] } 
      end
    end
  end        
end

# TODO might break SQL - https://blogs.msdn.microsoft.com/sql_server_team/understanding-the-requirements-for-sesecurityprivilege-to-sql-setup-account-on-remote-fileserver-when-default-backup-folder-is-set-to-unc-path/
control 'cis-backup-files-and-directories-2.2.8' do
  impact 0.7
  title '2.2.8 Set Back up files and directories to Administrators'
  tag cis: ['windows_2012r2:2.2.8', 'windows_2016:2.2.8', 'level1']
  ref 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0'
  ref 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.0.0'
  describe security_policy do
    its('SeSecurityPrivilege') { should include 'S-1-5-32-544' }
  end
end

control 'cis-change-system-time-2.2.9' do
  impact 0.7
  title '2.2.9 Set Change System Time to Administrators and Local Service'
  tag cis: ['windows_2012r2:2.2.9', 'windows_2016:2.2.9', 'level1']
  ref 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0'
  ref 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.0.0'
  describe security_policy do
    its('SeSystemtimePrivilege') { should eq ['S-1-5-32-544','S-1-5-19' }
  end
end

control 'cis-change-system-timezone-2.2.10' do
  impact 0.7
  title '2.2.10 Set Change System Timezone to Administrators and Local Service'
  tag cis: ['windows_2012r2:2.2.10', 'windows_2016:2.2.10', 'level1']
  ref 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0'
  ref 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.0.0'
  describe security_policy do
    its('SeTimeZonePrivilege') { should eq ['S-1-5-32-544','S-1-5-19' }
  end
end

control 'cis-create-page-file-2.2.11' do
  impact 0.7
  title '2.2.11 Ensure Create a Pagefile is set to Administrators'
  tag cis: ['windows_2012r2:2.2.11', 'windows_2016:2.2.11', 'level1']
  ref 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0'
  ref 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.0.0'
  describe security_policy do
    its('SeCreatePagefilePrivilege') { should eq 'S-1-5-32-544' }
  end
end

control 'cis-create-token-object-2.2.12' do
  impact 1
  title '2.2.12 Ensure Create a token object is set to No One'
  tag cis: ['windows_2012r2:2.2.12', 'windows_2016:2.2.12', 'level1']
  ref 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0'
  ref 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.0.0'
  describe security_policy do
    its('SeCreateTokenPrivilege') { should eq 'S-1-0-0' }
  end
end

control 'cis-create-global-objects-2.2.13' do
  impact 0.7
  title '2.2.13 Ensure Create global objects is set to LOCAL SERVICE, NETWORK SERVICE, Administrators, SERVICE'
  tag cis: ['windows_2012r2:2.2.13', 'windows_2016:2.2.13', 'level1']
  ref 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0'
  ref 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.0.0'
  describe security_policy do
    its('SeCreateGlobalPrivilege') { should eq '*S-1-5-19,*S-1-5-20,*S-1-5-32-544,*S-1-5-6' }
  end
end

control 'cis-create-permanent-shared-objects-2.2.14' do
  impact 0.7
  title '2.2.14 Ensure Create permanent shared objects is set to No One'
  tag cis: ['windows_2012r2:2.2.14', 'windows_2016:2.2.14', 'level1']
  ref 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0'
  ref 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.0.0'
  describe security_policy do
    its('SeCreatePermanentPrivilege') { should eq 'S-1-0-0' }
  end
end

control create-symbolic-links do
  impact 0.7
  title 'Configure Create symbolic links'
  tag cis: ['windows_2012r2:2.2.15', 'windows_2016:2.2.15', 'level1']
  ref 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0'
  ref 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.0.0'
  describe security_policy do
    its('SeCreateSymbolicLinkPrivilege') { should eq '*S-1-5-32-544,*S-1-5-83-0' }
  end
end

control debug-programs do
  impact 0.7
  title 'Ensure Debug programs is set to Administrators'
  tag cis: ['windows_2012r2:2.2.16', 'windows_2016:2.2.16', 'level1']
  ref 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0'
  ref 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.0.0'
  describe security_policy do
    its('SeDebugPrivilege') { should eq '*S-1-5-32-544' }
  end
end

control deny-access-to-computer-from-network do
  impact 0.7
  title 'Configure Deny access to this computer from the network'
  tag cis: ['windows_2012r2:2.2.17', 'windows_2016:2.2.17', 'level1']
  ref 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0'
  ref 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.0.0'
  describe security_policy do
    its('SeDenyNetworkLogonRight') { should eq 'Guest' }
  end
end

control deny-logon-as-batch-job do
  impact 0.7
  title 'Ensure Deny log on as a batch job to include Guests'
  tag cis: ['windows_2012r2:2.2.18', 'windows_2016:2.2.18', 'level1']
  ref 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0'
  ref 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.0.0'
  describe security_policy do
    its('SeDenyBatchLogonRight') { should eq 'Guest' }
  end
end

control deny-logon-as-service do
  impact 0.7
  title 'Ensure Deny log on as a service to include Guests'
  tag cis: ['windows_2012r2:2.2.19', 'windows_2016:2.2.19', 'level1']
  ref 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0'
  ref 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.0.0'
  describe security_policy do
    its('SeDenyServiceLogonRight') { should eq 'Guest' }
  end
end

control deny-logon-locally do
  impact 0.7
  title 'Ensure Deny log on locally to include Guests'
  tag cis: ['windows_2012r2:2.2.20', 'windows_2016:2.2.20', 'level1']
  ref 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0'
  ref 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.0.0'
  describe security_policy do
    its('SeDenyInteractiveLogonRight') { should eq 'Guest' }
  end
end

control deny-logon-rds do
  impact 0.7
  title 'Configure Deny log on through Remote Desktop Services'
  tag cis: ['windows_2012r2:2.2.21', 'windows_2016:2.2.21', 'level1']
  ref 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0'
  ref 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.0.0'
  describe security_policy do
    its('SeDenyRemoteInteractiveLogonRight') { should eq 'Guest' }
  end
end

control enable-accounts-trusted-for-delegation do
  impact 0.7
  title 'Configure Enable computer and user accounts to be trusted for delegation'
  tag cis: ['windows_2012r2:2.2.22', 'windows_2016:2.2.22', 'level1']
  ref 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0'
  ref 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.0.0'
  describe security_policy do
    its('SeEnableDelegationPrivilege') { should eq '*S-1-5-32-544' }
  end
end

control force-shutdown-from-remote do
  impact 0.7
  title 'Ensure Force shutdown from a remote system is set to Administrators '
  tag cis: ['windows_2012r2:2.2.23', 'windows_2016:2.2.23', 'level1']
  ref 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0'
  ref 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.0.0'
  describe security_policy do
    its('SeRemoteShutdownPrivilege') { should eq '*S-1-5-32-544' }
  end
end

control generate-security-audits do
  impact 0.7
  title 'Ensure Generate security audits is set to LOCAL SERVICE, NETWORK SERVICE'
  tag cis: ['windows_2012r2:2.2.24', 'windows_2016:2.2.24', 'level1']
  ref 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0'
  ref 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.0.0'
  describe security_policy do
    its('SeAuditPrivilege') { should eq '*S-1-5-19,*S-1-5-20' }
  end
end

control impersonate-a-client do
  impact 0.7
  title 'Configure Impersonate a client after authentication'
  tag cis: ['windows_2012r2:2.2.25', 'windows_2016:2.2.25', 'level1']
  ref 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0'
  ref 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.0.0'
  describe security_policy do
    its('SeImpersonatePrivilege') { should eq '*S-1-5-19,*S-1-5-20,*S-1-5-32-544,*S-1-5-6' }
  end
end

control increase-scheduling-priority do
  impact 0.7
  title 'Ensure Increase scheduling priority is set to Administrators'
  tag cis: ['windows_2012r2:2.2.26', 'windows_2016:2.2.26', 'level1']
  ref 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0'
  ref 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.0.0'
  describe security_policy do
    its('SeIncreaseBasePriorityPrivilege') { should eq '*S-1-5-32-544' }
  end
end

control load-and-unload-device-drives do
  impact 0.7
  title 'Ensure Load and unload device drivers is set to Administrators'
  tag cis: ['windows_2012r2:2.2.27', 'windows_2016:2.2.27', 'level1']
  ref 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0'
  ref 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.0.0'
  describe security_policy do
    its('SeLoadDriverPrivilege') { should eq '*S-1-5-32-544' }
  end
end

control lock-pages-in-memory do
  impact 0.7
  title 'Ensure Lock pages in memory is set to No One (Scored)'
  tag cis: ['windows_2012r2:2.2.28', 'windows_2016:2.2.28', 'level1']
  ref 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0'
  ref 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.0.0'
  describe security_policy do
    its('SeLockMemoryPrivilege') { should eq '*S-1-0-0' }
  end
end

control log-on-as-a-batch-job do
  impact 0.7
  title 'Ensure Log on as a batch job is set to Administrators (DC Only) '
  tag cis: ['windows_2012r2:2.2.29', 'windows_2016:2.2.29', 'level1']
  ref 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0'
  ref 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.0.0'
  describe security_policy do
    its('SeBatchLogonRight') { should eq '*S-1-5-32-544' }
  end
end

control manage-auditing-and-security-log do
  impact 0.7
  title 'Configure Manage auditing and security log'
  tag cis: ['windows_2012r2:2.2.30', 'windows_2016:2.2.30', 'level1']
  ref 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0'
  ref 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.0.0'
  describe security_policy do
    its('SeSecurityPrivilege') { should eq '*S-1-5-32-544' }
  end
end

control modify-an-object-label do
  impact 0.7
  title 'Ensure Modify an object label is set to No One'
  tag cis: ['windows_2012r2:2.2.31', 'windows_2016:2.2.31', 'level1']
  ref 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0'
  ref 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.0.0'
  describe security_policy do
    its('SeRelabelPrivilege') { should eq '*S-1-0-0' }
  end
end

control modify-firmware-environment-values do
  impact 0.7
  title 'Ensure Modify firmware environment values is set to Administrators'
  tag cis: ['windows_2012r2:2.2.32', 'windows_2016:2.2.32', 'level1']
  ref 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0'
  ref 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.0.0'
  describe security_policy do
    its('SeSystemEnvironmentPrivilege') { should eq '*S-1-5-32-544' }
  end
end

control perform-volume-maintenance-tasks do
  impact 0.7
  title 'Ensure Perform volume maintenance tasks is set to Administrators'
  tag cis: ['windows_2012r2:2.2.33', 'windows_2016:2.2.33', 'level1']
  ref 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0'
  ref 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.0.0'
  describe security_policy do
    its('SeManageVolumePrivilege') { should eq '*S-1-5-32-544' }
  end
end

control profile-single-process do
  impact 0.7
  title 'Ensure Profile single process is set to Administrators'
  tag cis: ['windows_2012r2:2.2.34', 'windows_2016:2.2.34', 'level1']
  ref 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0'
  ref 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.0.0'
  describe security_policy do
    its('SeProfileSingleProcessPrivilege') { should eq '*S-1-5-32-544' }
  end
end

control profile-system-performance do
  impact 0.7
  title 'Ensure Profile system performance is set to Administrators, NT SERVICE\WdiServiceHost'
  tag cis: ['windows_2012r2:2.2.35', 'windows_2016:2.2.35', 'level1']
  ref 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0'
  ref 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.0.0'
  describe security_policy do
    its('SeSystemProfilePrivilege') { should eq '*S-1-5-32-544,*S-1-5-80-3139157870-2983391045-3678747466-658725712-1809340420' }
  end
end

control replace-a-process-level-token do
  impact 0.7
  title 'Ensure Replace a process level token is set to LOCAL SERVICE, NETWORK SERVICE'
  tag cis: ['windows_2012r2:2.2.36', 'windows_2016:2.2.36', 'level1']
  ref 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0'
  ref 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.0.0'
  describe security_policy do
    its('SeAssignPrimaryTokenPrivilege') { should eq '*S-1-5-19,*S-1-5-20' }
  end
end

control restore-files-and-directories do
  impact 0.7
  title 'Ensure Restore files and directories is set to Administrators'
  tag cis: ['windows_2012r2:2.2.37', 'windows_2016:2.2.37', 'level1']
  ref 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0'
  ref 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.0.0'
  describe security_policy do
    its('SeRestorePrivilege') { should eq '*S-1-5-32-544' }
  end
end

control shutdown-the-system do
  impact 0.7
  title 'Ensure Shut down the system is set to Administrators'
  tag cis: ['windows_2012r2:2.2.38', 'windows_2016:2.2.38', 'level1']
  ref 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0'
  ref 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.0.0'
  describe security_policy do
    its('SeShutdownPrivilege') { should eq '*S-1-5-32-544' }
  end
end

control synchornize-directory-service-data do
  impact 0.7
  title 'Ensure Synchronize directory service data is set to No One'
  tag cis: ['windows_2012r2:2.2.39', 'windows_2016:2.2.39', 'level1']
  ref 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0'
  ref 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.0.0'
  describe security_policy do
    its('SeSyncAgentPrivilege') { should eq '*S-1-0-0' }
  end
end

control take-ownership-of-files-or-other-objects do
  impact 0.7
  title 'Ensure Take ownership of files or other objects is set to Administrators'
  tag cis: ['windows_2012r2:2.2.40', 'windows_2016:2.2.40', 'level1']
  ref 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0'
  ref 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.0.0'
  describe security_policy do
    its('SeTakeOwnershipPrivilege') { should eq '*S-1-5-32-544' }
  end
end