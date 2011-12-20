#ifdef UNICODE
#define DBGHELP_TRANSLATE_TCHAR
#endif

#include <Windows.h>
#include <DbgHelp.h>
#include <stdio.h>
#include <tchar.h>

CONTEXT Context;
STACKFRAME StackFrame;
PSYMBOL_INFOW pSymbol;
DEBUG_EVENT dbgEvent = { 0 };

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
						  GetModuleBaseRoutine, 0)) {
							  return TRUE; }
			else return FALSE; 
		 }

		 else return FALSE;
}

PSYMBOL_INFOW NTAPI SetSymbolInformationForAddress
	(__in HANDLE hProcess,
	 __in DWORD Address) {

		char buf[sizeof(PSYMBOL_INFOW) + MAX_SYM_NAME * sizeof(TCHAR)];
		ZeroMemory(buf, sizeof(buf));
        PSYMBOL_INFOW Symbol = (PSYMBOL_INFOW)buf;

        Symbol->SizeOfStruct = sizeof(SYMBOL_INFO);
        Symbol->MaxNameLen = MAX_SYM_NAME;

		if (SymFromAddrW(hProcess, Address, 0, Symbol)) {
			return Symbol; }
		else return NULL;
}

DWORD NTAPI OnAccessViolationException
	(__in HANDLE hThread,
	 __in HANDLE hProcess,
	 __in LPDEBUG_EVENT DbgEvent) {
		 	
		Context.ContextFlags = CONTEXT_INTEGER;
		if (GetThreadContext(hThread, &Context)) {
				printf("Edi %08x Esi %08x Ebx %08x ", Context.Edi, Context.Esi, Context.Ebx);
				printf("Edx %08x Ecx %08x Eax %08x\n", Context.Edx, Context.Ecx, Context.Eax); }
		Context.ContextFlags = CONTEXT_CONTROL;
		if (GetThreadContext(hThread, &Context)) {
				printf("Ebp %08x Eip %08x Esp %08x\n", Context.Ebp, Context.Eip, Context.Esp); }
		while (SetStackFrame(hProcess, hThread, StackFrame, &Context, SymFunctionTableAccess, SymGetModuleBase)) {
		     pSymbol = SetSymbolInformationForAddress(hProcess, StackFrame.AddrPC.Offset);
			 printf("Flags: %08x\n", &pSymbol->Flags);
			 //printf("NameLen: %d\n", pSymbol->NameLen);
			 _tprintf(_T("Name: %s\n"), &pSymbol->Name[0]); } 
			 

		return DBG_EXCEPTION_NOT_HANDLED;
}

BOOL NTAPI SetDbgEvents
	(__in LPDEBUG_EVENT DbgEvent) {

		HANDLE hProcess, hThread;
		DWORD dwContinueStatus = DBG_CONTINUE;

		for (;;) {
			if (WaitForDebugEvent(DbgEvent, INFINITE)) {
				hThread = OpenThread(THREAD_SET_CONTEXT | THREAD_GET_CONTEXT,
								     FALSE, DbgEvent->dwThreadId);
				hProcess = OpenProcess(PROCESS_ALL_ACCESS,
								       FALSE, DbgEvent->dwThreadId);				
		        SetThreadContext(hThread, &Context);
				SymInitialize(hProcess, NULL, FALSE);
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

				default:
					break;
				}
				CloseHandle(hThread);

			}
			if (dwContinueStatus == DBG_EXCEPTION_NOT_HANDLED) {
				printf("Exception not handled!\n");
				DebugBreakProcess(hProcess); }
			else ContinueDebugEvent(DbgEvent->dwProcessId, DbgEvent->dwThreadId, dwContinueStatus); 
            CloseHandle(hProcess);
		}
}

NTSTATUS __cdecl main
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

			              


