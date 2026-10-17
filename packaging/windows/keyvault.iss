; Inno Setup 6 script for the KeyVault installer.
; Built by scripts\build-windows.ps1, which passes:
;   /DAppVersion=0.1.0 /DArch=x64|arm64 /DArchAllowed=x64compatible|arm64
;   /DSourceExe=<path to keyvault.exe> /DOutDir=<dist folder>

#ifndef AppVersion
  #define AppVersion "0.1.0"
#endif
#ifndef Arch
  #define Arch "x64"
#endif
#ifndef ArchAllowed
  #define ArchAllowed "x64compatible"
#endif
#ifndef SourceExe
  #define SourceExe "..\..\target\release\keyvault.exe"
#endif
#ifndef OutDir
  #define OutDir "..\..\dist"
#endif

[Setup]
AppId={{6C1B7E52-3F0A-4C8E-9D4B-7A2E5F1C9B30}
AppName=KeyVault
AppVersion={#AppVersion}
AppVerName=KeyVault {#AppVersion}
AppPublisher=KeyVault
DefaultDirName={autopf}\KeyVault
DefaultGroupName=KeyVault
DisableProgramGroupPage=yes
; Per-user install by default (no admin prompt); the user can choose all users.
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
ArchitecturesAllowed={#ArchAllowed}
ArchitecturesInstallIn64BitMode={#ArchAllowed}
MinVersion=10.0.17763
OutputDir={#OutDir}
OutputBaseFilename=KeyVault-{#AppVersion}-windows-{#Arch}-setup
SetupIconFile=keyvault.ico
UninstallDisplayIcon={app}\KeyVault.exe
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
Source: "{#SourceExe}"; DestDir: "{app}"; DestName: "KeyVault.exe"; Flags: ignoreversion

[Icons]
Name: "{autoprograms}\KeyVault"; Filename: "{app}\KeyVault.exe"
Name: "{autodesktop}\KeyVault"; Filename: "{app}\KeyVault.exe"; Tasks: desktopicon

[Run]
Filename: "{app}\KeyVault.exe"; Description: "{cm:LaunchProgram,KeyVault}"; Flags: nowait postinstall skipifsilent

; Your vault (%APPDATA%\keyvault) is NOT removed on uninstall, so keys are never lost by accident.
