Unicode true
RequestExecutionLevel user
!include "MUI2.nsh"
!include "LogicLib.nsh"

!ifndef BINARY
  !error "BINARY must point to the vpnpa executable"
!endif
!ifndef OUTPUT
  !error "OUTPUT must name the installer"
!endif
!ifndef VERSION
  !define VERSION "0.0.0"
!endif

Name "vpnpa"
OutFile "${OUTPUT}"
InstallDir "$LOCALAPPDATA\Programs\vpnpa"
InstallDirRegKey HKCU "Software\vpnpa" "InstallDir"
ShowInstDetails show
ShowUninstDetails show

!define MUI_ABORTWARNING
!define MUI_FINISHPAGE_RUN "$INSTDIR\vpnpa.exe"
!define MUI_FINISHPAGE_RUN_TEXT "Запустить vpnpa"
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_LANGUAGE "Russian"
!insertmacro MUI_LANGUAGE "English"

Section "vpnpa" SecApp
  SetShellVarContext current
  InitPluginsDir
  SetOutPath "$PLUGINSDIR"
  File /oname=vpnpa-stop.exe "${BINARY}"
  ClearErrors
  ExecWait '"$PLUGINSDIR\vpnpa-stop.exe" installer-stop' $0
  IfErrors stop_failed
  ${If} $0 != 0
  stop_failed:
    MessageBox MB_ICONSTOP "Не удалось остановить работающий vpnpa. Закройте программу и повторите установку."
    Abort
  ${EndIf}
  SetOutPath "$INSTDIR"
  File /oname=vpnpa.exe "${BINARY}"
  WriteUninstaller "$INSTDIR\Uninstall.exe"
  CreateDirectory "$SMPROGRAMS\vpnpa"
  CreateShortcut "$SMPROGRAMS\vpnpa\vpnpa.lnk" "$INSTDIR\vpnpa.exe"
  WriteRegStr HKCU "Software\vpnpa" "InstallDir" "$INSTDIR"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Run" "vpnpa" '"$INSTDIR\vpnpa.exe" tray'
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\vpnpa" "DisplayName" "vpnpa"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\vpnpa" "DisplayVersion" "${VERSION}"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\vpnpa" "Publisher" "LDPet"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\vpnpa" "DisplayIcon" "$INSTDIR\vpnpa.exe"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\vpnpa" "UninstallString" '"$INSTDIR\Uninstall.exe"'
  WriteRegDWORD HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\vpnpa" "NoModify" 1
  WriteRegDWORD HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\vpnpa" "NoRepair" 1
SectionEnd

Section "Uninstall"
  SetShellVarContext current
  IfFileExists "$INSTDIR\vpnpa.exe" 0 remove_registration
  ClearErrors
  ExecWait '"$INSTDIR\vpnpa.exe" installer-stop' $0
  IfErrors uninstall_failed
  ${If} $0 != 0
    Goto uninstall_failed
  ${EndIf}
  ClearErrors
  Delete "$INSTDIR\vpnpa.exe"
  IfErrors uninstall_failed
  Goto remove_registration
  uninstall_failed:
    MessageBox MB_ICONSTOP "Не удалось остановить или удалить vpnpa. Закройте программу и повторите удаление."
    Abort
  remove_registration:
  DeleteRegValue HKCU "Software\Microsoft\Windows\CurrentVersion\Run" "vpnpa"
  DeleteRegKey HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\vpnpa"
  DeleteRegKey HKCU "Software\vpnpa"
  Delete "$SMPROGRAMS\vpnpa\vpnpa.lnk"
  RMDir "$SMPROGRAMS\vpnpa"
  Delete "$INSTDIR\vpnpa.exe.old"
  Delete "$INSTDIR\Uninstall.exe"
  RMDir "$INSTDIR"
SectionEnd
