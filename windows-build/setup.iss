; Inno-Setup-Skript fuer SurfWolf74 (Windows-Installer).
; Wird von der GitHub-Action gebaut; Version kommt via /DMyAppVersion=... rein.
; SourceDir ist standardmaessig der Ordner dieses Skripts (windows-build/),
; daher zeigen die ..\-Pfade auf den Projekt-Root.

#define MyAppName "SurfWolf74"
#ifndef MyAppVersion
  #define MyAppVersion "0.0"
#endif
#define MyAppPublisher "Wolfram Consult GmbH & Co. KG"
#define MyAppURL "https://github.com/Wolfram33/surfwolf74"
#define MyAppExeName "surfwolf74.exe"

[Setup]
; Stabile AppId (nicht aendern - sonst erkennt der Installer Updates nicht)
AppId={{7F3A9C21-4B8E-4E2A-9D6F-1C5B2A0E8D74}}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
DefaultDirName={autopf}\SurfWolf74
DefaultGroupName=SurfWolf74
DisableProgramGroupPage=yes
UninstallDisplayIcon={app}\{#MyAppExeName}
OutputDir=..\dist
OutputBaseFilename=SurfWolf74-Setup
Compression=lzma2
SolidCompression=yes
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
WizardStyle=modern
SetupIconFile=..\icon.ico

[Languages]
Name: "german"; MessagesFile: "compiler:Languages\German.isl"
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
; Gesamten Nuitka-Standalone-Ordner uebernehmen
Source: "..\surfwolf74.dist\*"; DestDir: "{app}"; Flags: recursesubdirs createallsubdirs ignoreversion

[Icons]
Name: "{group}\SurfWolf74"; Filename: "{app}\{#MyAppExeName}"
Name: "{group}\{cm:UninstallProgram,SurfWolf74}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\SurfWolf74"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchProgram,SurfWolf74}"; Flags: nowait postinstall skipifsilent
