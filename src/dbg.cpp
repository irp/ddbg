#define DBGHELP_TRANSLATE_TCHAR

#include <Windows.h>
#include <DbgHelp.h>
#include <stdio.h>
#include <tchar.h>

CONTEXT Context;
STACKFRAME StackFrame;
DEBUG_EVENT dbgEvent = { 0 };
MEMORY_BASIC_INFORMATION lpBuffer;

BOOL NTAPI SetStackFrame
	(__in      HANDLE hProcess,
         __in      HANDLE hThread,
         __inout   STACKFRAME stackFrame,
         __inout   PCONTEXT context,
         __in_opt  PFUNCTION_TABLE_ACCESS_ROUTINE FunctionTableAccessRoutine,
         __in_opt  PGET_MODULE_BASE_ROUTINE GetModuleBaseRoutine) {

	         ZeroMemory(&stackFrame, sizeof(stackFrame));
		 if (context != NULL) {

	         stackFrame.AddrPC.Offset = context->Eip;
	         stackFrame.AddrPC.Mode = AddrModeFlat;
	         stackFrame.AddrStack.Offset = context->Esp;
	         stackFrame.AddrStack.Mode = AddrModeFlat;
	         stackFrame.AddrFrame.Offset = context->Ebp;
	         stackFrame.AddrFrame.Mode = AddrModeFlat; }

		 //Note: MachineType IMAGE_FILE_MACHINE_I386
		 //so if I've no context I've to initialize the 
		 //stack frame in another way, reading from asm code
		 else {

			 ULONG programCoun, pStack, pBase;

			 __asm {
				 pop [programCoun]
				 mov [pStack], esp
				 mov [pBase], ebp }

			 stackFrame.AddrPC.Offset = programCoun;
	                 stackFrame.AddrPC.Mode = AddrModeFlat;
	                 stackFrame.AddrStack.Offset = pStack;
	                 stackFrame.AddrStack.Mode = AddrModeFlat;
	                 stackFrame.AddrFrame.Offset = pBase;
			 stackFrame.AddrFrame.Mode = AddrModeFlat; }

		 if (hProcess != INVALID_HANDLE_VALUE) {
			if (StackWalk(IMAGE_FILE_MACHINE_I386, hProcess, hThread, 
				      &StackFrame, context, 0, FunctionTableAccessRoutine, 
				      GetModuleBaseRoutine, 0)) {          return TRUE;               }
				      
			else return FALSE; 
		 }

		 else return FALSE;
}

DWORD NTAPI OnAccessViolationException
	(__in HANDLE hThread,
	 __in HANDLE hProcess,
	 __in LPDEBUG_EVENT DbgEvent) {

        PSYMBOL_INFOW pSymbol;
	char buf[sizeof(PSYMBOL_INFOW) + MAX_SYM_NAME * sizeof(TCHAR)];
	ZeroMemory(buf, sizeof(buf));
        pSymbol = (PSYMBOL_INFOW)buf;

        pSymbol->SizeOfStruct = sizeof(SYMBOL_INFO);
        pSymbol->MaxNameLen = MAX_SYM_NAME;

        if (SymFromAddrW(hProcess, StackFrame.AddrPC.Offset, 0, pSymbol)) {

		 Context.ContextFlags = CONTEXT_INTEGER;
		 if (GetThreadContext(hThread, &Context)) {
		       printf("Edi %08x Esi %08x Ebx %08x ", Context.Edi, Context.Esi, Context.Ebx);
		       printf("Edx %08x Ecx %08x Eax %08x\n", Context.Edx, Context.Ecx, Context.Eax); }
		 Context.ContextFlags = CONTEXT_CONTROL;
		 if (GetThreadContext(hThread, &Context)) {
		      printf("Ebp %08x Eip %08x Esp %08x\n", Context.Ebp, Context.Eip, Context.Esp); }
		      while (SetStackFrame(hProcess, hThread, StackFrame, &Context, 
		                           SymFunctionTableAccess, SymGetModuleBase)) {
                         printf("nameLen: %d\n", pSymbol->NameLen);
			 printf("Flags: %08x\n", pSymbol->Flags);
			 _tprintf(_T("Name: %s\n"), pSymbol->Name);
			 
		       }
		 }
		 else printf("ERROR: SymFromAddrW failed with code: %d\n", GetLastError());

	return DBG_EXCEPTION_NOT_HANDLED;
}

BOOL NTAPI SetDbgEvents
	(__in LPDEBUG_EVENT DbgEvent) {

	HANDLE hProcess, hThread;
	DWORD dwContinueStatus = DBG_CONTINUE, oldProtection;
	PVOID pImageName, pBaseOfDll;
	WCHAR  ImageName;
	ULONG_PTR sizeRead, szRead;
	BOOL value;

	for (;;) {
		if (WaitForDebugEvent(DbgEvent, INFINITE)) {
		    hThread = OpenThread(THREAD_SET_CONTEXT | THREAD_GET_CONTEXT,
					 FALSE, DbgEvent->dwThreadId);
	            hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_ALL_ACCESS | PROCESS_VM_OPERATION,
					   FALSE, DbgEvent->dwProcessId);				
		    SetThreadContext(hThread, &Context);
		    SymInitializeW(hProcess, NULL, FALSE);
		    switch (DbgEvent->dwDebugEventCode) {
		    case EXCEPTION_DEBUG_EVENT:
			switch (DbgEvent->u.Exception.ExceptionRecord.ExceptionCode) {
			case EXCEPTION_ACCESS_VIOLATION:
				printf("EXCEPTION_ACCESS_VIOLATION\n");			
				SuspendThread(hThread);
				if (DbgEvent->u.Exception.dwFirstChance == 1) printf("!!First chance!!\n");
				dwContinueStatus = OnAccessViolationException(hThread, hProcess, DbgEvent);
				ResumeThread(hThread);
				break;

			default:
			        break;
		          }
				    break;
		    case LOAD_DLL_DEBUG_EVENT:
		    VirtualProtectEx(hProcess, DbgEvent->u.LoadDll.lpImageName, sizeof(DbgEvent->u.LoadDll.lpImageName), 
			             PAGE_READONLY, &oldProtection);
                    value = ReadProcessMemory(hProcess, DbgEvent->u.LoadDll.lpImageName, 
			                      &pImageName, sizeof(DbgEvent->u.LoadDll.lpImageName), &sizeRead);
		    if (value == FALSE)     printf("ERROR: ReadProcessMemory failed reading lpImageName: %d\n", GetLastError());
	           
	            if (pImageName != NULL) {
	            	
		         if (ReadProcessMemory(hProcess, &pImageName, &ImageName, lpBuffer.RegionSize, &szRead)) {
				  VirtualProtectEx(hProcess, DbgEvent->u.LoadDll.lpBaseOfDll, sizeof(DbgEvent->u.LoadDll.lpBaseOfDll), 
						   PAGE_READONLY, &oldProtection);
				  ReadProcessMemory(hProcess, DbgEvent->u.LoadDll.lpBaseOfDll,
				                    &pBaseOfDll, sizeof(DbgEvent->u.LoadDll.lpBaseOfDll), &sizeRead);
		                  SymLoadModuleExW(hProcess, DbgEvent->u.LoadDll.hFile, &ImageName, NULL, 
			                          (DWORD)DbgEvent->u.LoadDll.lpBaseOfDll, szRead, NULL, 0);
									
                         }
			 else printf("ERROR: ReadProcessMemory failed reading the module name!\n");
	            }
		    else printf("ERROR: pImageName is NULL!\n");

		    default:
			break;
		    }
		    CloseHandle(hThread);

		}
			if (dwContinueStatus == DBG_EXCEPTION_NOT_HANDLED) {
				printf("ERROR: Exception not handled!\n");
				DebugBreakProcess(hProcess); }
			else ContinueDebugEvent(DbgEvent->dwProcessId, DbgEvent->dwThreadId, dwContinueStatus); 
                        CloseHandle(hProcess);
		}
}

int __cdecl main
	() {

        PROCESS_INFORMATION procInfo;
	STARTUPINFO startupInfo; 
 
        ZeroMemory(&startupInfo, sizeof(startupInfo)); 
        startupInfo.cb = sizeof(startupInfo); 
        ZeroMemory(&procInfo, sizeof(procInfo));

	printf("Welocome to dbg\n");
	if (CreateProcessW(L"C:\\jump.exe", NULL, NULL, NULL, 
			   FALSE, DEBUG_ONLY_THIS_PROCESS, NULL,
			   NULL, &startupInfo, &procInfo)) {

			if (SetDbgEvents(&dbgEvent)) {

			 }
	}

	int c = getchar();
	return 0;
}

			              



