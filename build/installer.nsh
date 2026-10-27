; Muse installer customization (electron-builder NSIS include).
;
; Adds one custom page after the install-directory page: the user picks
; WHERE the Muse folder should live (a parent location). A folder named
; "Muse" is created in that location, with "Workspace" and "Shared"
; subfolders inside it - that Muse folder is Muse's home folder on
; this PC (its workspace, shared files, and storage cap all apply to it).
;
; The choice is handed to the app by writing assistant-folder.txt into the
; app's userData folder (%APPDATA%\Muse). The file holds the FINAL
; assistant folder path (<picked location>\Muse). On first run the app
; folds that path into settings.json and deletes the hand-off file, so
; settings.json is the single source of truth afterwards. (A plain text
; hand-off avoids JSON string-escaping problems in NSIS.) If the field is
; left blank, the default location is used and the app falls back to
; %USERPROFILE%\Muse.
;
; Pure ASCII on purpose: NSIS reads scripts as ANSI unless a BOM is present.

!include nsDialogs.nsh

; Nothing below may exist in the BUILD_UNINSTALLER pass: that pass never
; inserts the page or the customInstall macro, and makensis (warnings
; treated as errors) fails the build on the resulting "not referenced"
; warnings 6001/6010. In the installer pass everything is referenced.
!ifndef BUILD_UNINSTALLER

Var AssistantParentPath
Var AssistantFolderPath
Var AssistantFolderDialog
Var AssistantFolderField
Var AssistantFolderHandle

Function MuseAssistantFolderPageCreate
  StrCpy $AssistantParentPath "$PROFILE"
  nsDialogs::Create 1018
  Pop $AssistantFolderDialog
  StrCmp $AssistantFolderDialog error 0 create_ok
  Abort
  create_ok:

  ${NSD_CreateLabel} 0 0 100% 22u "Choose where the Muse folder should live - a folder named 'Muse' will be created in this location, with Workspace and Shared folders inside it. That Muse folder is Muse's home folder on this PC."
  Pop $0
  ${NSD_CreateText} 0 26u 76% 12u "$AssistantParentPath"
  Pop $AssistantFolderField
  ${NSD_CreateButton} 78% 26u 22% 12u "Browse..."
  Pop $0
  ${NSD_OnClick} $0 MuseAssistantFolderBrowse
  ${NSD_CreateLabel} 0 46u 100% 22u "You can move it later in the app (tray menu - Assistant Folder and Storage). Leaving the default is fine."
  Pop $0

  nsDialogs::Show
FunctionEnd

Function MuseAssistantFolderBrowse
  nsDialogs::SelectFolderDialog "Select where the Muse folder should live" "$AssistantParentPath"
  Pop $0
  StrCmp $0 error browse_done
  StrCpy $AssistantParentPath $0
  ${NSD_SetText} $AssistantFolderField "$AssistantParentPath"
  browse_done:
FunctionEnd

Function MuseAssistantFolderPageLeave
  ${NSD_GetText} $AssistantFolderField $AssistantParentPath
  StrCmp $AssistantParentPath "" 0 parent_ok
  StrCpy $AssistantParentPath "$PROFILE"
  parent_ok:
  StrCpy $AssistantFolderPath "$AssistantParentPath\Muse"
FunctionEnd

!macro customPageAfterChangeDir
  Page custom MuseAssistantFolderPageCreate MuseAssistantFolderPageLeave
!macroend

!macro customInstall
  ; If the custom page never ran, fall back to the default here too.
  StrCmp $AssistantFolderPath "" 0 install_write
  StrCpy $AssistantFolderPath "$PROFILE\Muse"
  install_write:

  ; Persist the choice where the app will find it on first run.
  CreateDirectory "$APPDATA\Muse"
  FileOpen $AssistantFolderHandle "$APPDATA\Muse\assistant-folder.txt" w
  FileWrite $AssistantFolderHandle "$AssistantFolderPath"
  FileClose $AssistantFolderHandle

  ; Create the assistant folder itself at install time, with its two
  ; subfolders (the app also ensures them on first run).
  CreateDirectory "$AssistantFolderPath"
  CreateDirectory "$AssistantFolderPath\Workspace"
  CreateDirectory "$AssistantFolderPath\Shared"
!macroend

!endif ; BUILD_UNINSTALLER
