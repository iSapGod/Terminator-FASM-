format PE GUI 4.0
entry start

include 'win32a.inc'

section '.data' data readable writeable

TOKEN_ADJUST_PRIVILEGES = 20h
TOKEN_QUERY		= 8h
SE_PRIVILEGE_ENABLED	= 2h

struct LUID
    lowPart		dd ?
    HighPart		dd ?
ends

struct LUID_AND_ATTRIBUTES
    pLuid		LUID
    Attributes		dd ?
ends

struct _TOKEN_PRIVILEGES
    PrivilegeCount	dd ?
    Privileges		LUID_AND_ATTRIBUTES
ends

struct PROCESSENTRY32
    dwSize		dd ?
    cntUsage		dd ?
    th32ProcessID	dd ?
    th32DefaultHeapID	dd ?
    th32ModuleID	dd ?
    cntThreads		dd ?
    th32ParentProcessID dd ?
    pcPriClassBase	dd ?
    dwFlags		dd ?
    szExeFile		rb MAX_PATH
    th32MemoryBase	dd ?
    th32AccessKey	dd ?
ends

TH32CS_SNAPPROCESS = 0x00000002


udtLUID 	LUID
tkp		_TOKEN_PRIVILEGES

ProcEntry	PROCESSENTRY32

TTokenHd	dd ?
tmp		dd ?

ID_DEC		= 101


section '.code' code readable executable

start:
	call  GetConsoleProcessList
	invoke	GetCurrentProcess
	invoke	OpenProcessToken,eax,TOKEN_ADJUST_PRIVILEGES+TOKEN_QUERY,TTokenHd
	or	eax,eax
	jz	loc_exit

	invoke	LookupPrivilegeValue,NULL,SE_DEBUG_NAME,udtLUID
	or	eax,eax
	jz	loc_exit

	mov	[tkp.PrivilegeCount],1
	mov	[tkp.Privileges.Attributes],SE_PRIVILEGE_ENABLED
	mov	eax,[udtLUID.lowPart]
	mov	[tkp.Privileges.pLuid.lowPart],eax
	mov	eax,[udtLUID.HighPart]
	mov	[tkp.Privileges.pLuid.HighPart],eax
	invoke	AdjustTokenPrivileges,[TTokenHd],0,tkp,0,0,0
	or	eax,eax
	jz	loc_exit

	invoke	GetModuleHandle,0
	invoke	DialogBoxParam,eax,37,HWND_DESKTOP,DialogProc,0

loc_exit:
	invoke	ExitProcess,0

SE_DEBUG_NAME	db 'SeDebugPrivilege',0


proc DialogProc hwnddlg,msg,wparam,lparam
	push	ebx esi edi
	cmp	[msg],WM_INITDIALOG
	je	.wminitdialog
	cmp	[msg],WM_COMMAND
	je	.wmcommand
	cmp	[msg],WM_CLOSE
	je	.wmclose
	xor	eax,eax
	jmp	.finish
  .wminitdialog:
	jmp	.processed
  .wmcommand:
	cmp	[wparam],BN_CLICKED shl 16 + IDCANCEL
	je	.wmclose
	cmp	[wparam],BN_CLICKED shl 16 + IDOK
	je	.wmkill
	jmp	.processed

  .wmkill:
	invoke	GetDlgItemInt,[hwnddlg],ID_DEC,NULL,FALSE
	or	eax,eax
	jz	.processed

	stdcall KillProcess,eax,TRUE

	jmp	.processed

  .wmclose:
	invoke	EndDialog,[hwnddlg],0
  .processed:
	mov	eax,1
  .finish:
	pop	edi esi ebx
	ret
endp

proc	KillProcess pID:DWORD,recursive:DWORD
	pusha

	cmp	[recursive],TRUE
	jne	.kill_process

	invoke	CreateToolhelp32Snapshot,TH32CS_SNAPPROCESS,0
	mov	ebx,eax

	mov	[ProcEntry.dwSize],sizeof.PROCESSENTRY32
	invoke	Process32First,ebx,ProcEntry
.check_process:
	cmp	eax,FALSE
	je	.stop_scan

	mov	eax,[ProcEntry.th32ParentProcessID]
	cmp	eax,[pID]
	jne	.next_process

	stdcall KillProcess,[ProcEntry.th32ProcessID],[recursive]
.next_process:
	invoke	Process32Next,ebx,ProcEntry
	jmp	.check_process
.stop_scan:
	invoke	CloseHandle,ebx
.kill_process:
	invoke	GetCurrentProcessId
	cmp	eax,[pID]
	je	@f
	invoke	OpenProcess,PROCESS_TERMINATE,FALSE,[pID]
	or	eax,eax
	jz	@f
	invoke	TerminateProcess,eax,0
@@:

	popa
	ret
endp



section '.idata' import data readable writeable

  library kernel32,'kernel32.dll',\
	  user32,'user32.dll',\
	  advapi32,'advapi32.dll'

  include 'api\kernel32.inc'
  include 'api\user32.inc'
  include 'api\advapi32.inc'

section '.rsrc' resource data readable

  directory RT_DIALOG,dialogs

  resource dialogs,\
	   37,LANG_ENGLISH+SUBLANG_DEFAULT,demonstration

  dialog demonstration,'When process dies..',0,0,190,58,WS_CAPTION+WS_SYSMENU+DS_CENTER
    dialogitem 'BUTTON','',-1, 2, -1, 185, 37,WS_VISIBLE+BS_GROUPBOX

    dialogitem 'STATIC','ProcID:',-1,5,16,45,12,WS_VISIBLE+SS_RIGHT
    dialogitem 'EDIT','',ID_DEC,55,14,110,12,WS_CHILD+WS_VISIBLE+ES_CENTER+ES_NUMBER+WS_BORDER

    dialogitem 'BUTTON',"Kill it!",IDOK,70,40,60,15,WS_VISIBLE+WS_TABSTOP+BS_PUSHBUTTON
    dialogitem 'BUTTON','Exit',IDCANCEL,135,40,50,15,WS_VISIBLE+WS_TABSTOP+BS_PUSHBUTTON
  enddialog