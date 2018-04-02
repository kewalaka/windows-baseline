
msoffice_present = attribute('msoffice_present', default: false, description: 'Should we control presence of Microsoft msoffice')
msoffice_version = attribute('msoffice_version', default: '16.0', description: 'Which Microsoft msoffice version do we control?')
msoffice_vbawarnings = attribute('msoffice_vbawarnings', default: 3, description: 'Minimum level for vbawarnings')

if msoffice_present
  title 'Microsoft office'
  # ref url: 'https://www.asd.gov.au/publications/protect/hardening-ms-office-2016.htm'
  # ref url: 'https://www.asd.gov.au/publications/protect/ms-office-macro-security.htm'

  control 'msoffice-outlook-1' do
    impact 0.7
    title 'Outlook'
    desc 'silently disable OLE Package function in Outlook'
    ref url: 'https://doublepulsar.com/oleoutlook-bypass-almost-every-corporate-security-control-with-a-point-n-click-gui-37f4cbc107d0'
    describe registry_key("HKCU\\SOFTWARE\\Microsoft\\Office\\#{msoffice_version}\\Outlook\\Security") do
      it { should exist }
      its('ShowOLEPackageObj') { should eq 0 }
    end
  end

  control 'msoffice-2' do
    impact 0.7
    title 'Macro settings'
    desc 'Disable Macros with notification unless signed'
    ref url: 'https://blogs.technet.microsoft.com/diana_tudor/2014/12/02/microsoft-project-how-to-control-macro-settings-using-registry-keys/'
    describe registry_key("HKCU\\SOFTWARE\\Policies\\Microsoft\\Office\\#{msoffice_version}\\Word\\Security") do
      it { should exist }
      its('VBAWarnings') { should >= msoffice_vbawarnings }
      its('blockcontentexecutionfrominternet') { should eq 1 }
    end
    describe registry_key("HKCU\\SOFTWARE\\Policies\\Microsoft\\Office\\#{msoffice_version}\\Excel\\Security") do
      it { should exist }
      its('VBAWarnings') { should >= msoffice_vbawarnings }
      its('blockcontentexecutionfrominternet') { should eq 1 }
    end
    describe registry_key("HKCU\\SOFTWARE\\Policies\\Microsoft\\Office\\#{msoffice_version}\\Powerpoint\\Security") do
      it { should exist }
      its('VBAWarnings') { should >= msoffice_vbawarnings }
      its('blockcontentexecutionfrominternet') { should eq 1 }
    end
    describe registry_key("HKCU\\SOFTWARE\\Policies\\Microsoft\\Office\\#{msoffice_version}\\Access\\Security") do
      it { should exist }
      its('VBAWarnings') { should >= msoffice_vbawarnings }
      its('blockcontentexecutionfrominternet') { should eq 1 }
    end
    describe registry_key("HKCU\\SOFTWARE\\Policies\\Microsoft\\Office\\#{msoffice_version}\\Publisher\\Security") do
      it { should exist }
      its('VBAWarnings') { should >= msoffice_vbawarnings }
      its('blockcontentexecutionfrominternet') { should eq 1 }
    end
    describe registry_key("HKCU\\SOFTWARE\\Policies\\Microsoft\\Office\\#{msoffice_version}\\Visio\\Security") do
      it { should exist }
      its('VBAWarnings') { should >= msoffice_vbawarnings }
      its('blockcontentexecutionfrominternet') { should eq 1 }
    end
  end

  control 'msoffice-3' do
    impact 0.7
    title 'Outlook'
    desc 'Ensure protected view is enabled '
    describe registry_key("HKCU\\SOFTWARE\\Microsoft\\Office\\#{msoffice_version}\\Outlook\\Security") do
      it { should exist }
      its('MarkInternalAsUnsafe') { should eq 1 }
    end
    describe registry_key("HKCU\\SOFTWARE\\Policies\\Microsoft\\Office\\#{msoffice_version}\\Outlook\\Security") do
      it { should exist }
      its('MarkInternalAsUnsafe') { should eq 1 }
    end
    describe registry_key("HKCU\\SOFTWARE\\Microsoft\\Office\\#{msoffice_version}\\Word\\Security\\ProtectedView") do
      it { should exist }
      its('DisableAttachementsInPV') { should eq 0 }
      its('DisableInternetFilesInPV') { should eq 0 }
      its('DisableUnsafeLocationsInPV') { should eq 0 }
    end
    describe registry_key("HKCU\\SOFTWARE\\Microsoft\\Office\\#{msoffice_version}\\Excel\\Security\\ProtectedView") do
      it { should exist }
      its('DisableAttachementsInPV') { should eq 0 }
      its('DisableInternetFilesInPV') { should eq 0 }
      its('DisableUnsafeLocationsInPV') { should eq 0 }
    end
    describe registry_key("HKCU\\SOFTWARE\\Microsoft\\Office\\#{msoffice_version}\\PowerPoint\\Security\\ProtectedView") do
      it { should exist }
      its('DisableAttachementsInPV') { should eq 0 }
      its('DisableInternetFilesInPV') { should eq 0 }
      its('DisableUnsafeLocationsInPV') { should eq 0 }
    end
  end

  control 'msproject-1' do
    impact 0.7
    title 'Ms Project'
    desc 'Disable Macros with notifications'
    ref url: 'https://blogs.technet.microsoft.com/diana_tudor/2014/12/02/microsoft-project-how-to-control-macro-settings-using-registry-keys/'
    describe registry_key("HKCU\\SOFTWARE\\Policies\\Microsoft\\Office\\#{msoffice_version}\\msproject\\Security") do
      it { should exist }
      its('VBAWarnings') { should >= 2 }
    end
  end

  control 'msoffice-dde-1' do
    impact 0.7
    title 'Disable DDE functions'
    desc ''
    ref url: 'https://technet.microsoft.com/en-us/library/security/4053440'
    describe registry_key("HKCU\\SOFTWARE\\Microsoft\\Office\\#{msoffice_version}\\Word\\Options") do
      it { should exist }
      its('DontUpdateLinks') { should eq 1 }
    end
    describe registry_key("HKCU\\SOFTWARE\\Microsoft\\Office\\#{msoffice_version}\\Word\\Options\\WordMail") do
      it { should exist }
      its('DontUpdateLinks') { should eq 1 }
    end
    describe registry_key("HKCU\\SOFTWARE\\Microsoft\\Office\\#{msoffice_version}\\Excel\\Options") do
      it { should exist }
      its('DontUpdateLinks') { should eq 1 }
    end
    describe registry_key("HKCU\\SOFTWARE\\Microsoft\\Office\\#{msoffice_version}\\Excel\\Security") do
      it { should exist }
      its('WorkbookLinkWarnings') { should eq 2 }
    end
  end

  control 'msoffice-4' do
    impact 0.7
    title 'Disable Equation Editor'
    desc ''
    ref url: 'https://embedi.com/blog/skeleton-closet-ms-office-vulnerability-you-didnt-know-about'
    describe registry_key("HKLM\\SOFTWARE\\Microsoft\\Office\\#{msoffice_version}\\Common\\COM Compatibility\\{0002CE02-0000- 0000-C000-000000000046}") do
      it { should exist }
      its('Compatibility Flags') { should eq 0x400 }
    end
    describe registry_key("HKLM\\SOFTWARE\\Wow6432Node\\Microsoft\\Office\\#{msoffice_version}\\Common\\COM Compatibility\\{0002CE02-0000- 0000-C000-000000000046}") do
      it { should exist }
      its('Compatibility Flags') { should eq 0x400 }
    end
  end

end
