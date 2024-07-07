
rule Backdoor_Win64_TurlaCarbon{
	meta:
		description = "Backdoor:Win64/TurlaCarbon,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 23 00 00 "
		
	strings :
		$a_80_0 = {53 59 53 54 45 4d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 73 65 72 76 69 63 65 73 5c 57 69 6e 52 65 73 53 76 63 5c 50 61 72 61 6d 65 74 65 72 73 } //SYSTEM\CurrentControlSet\services\WinResSvc\Parameters  1
		$a_80_1 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 53 76 63 68 6f 73 74 } //SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost  1
		$a_80_2 = {53 65 74 20 76 69 63 74 69 6d 20 55 55 49 44 20 74 6f } //Set victim UUID to  1
		$a_80_3 = {53 65 74 20 75 70 20 70 65 65 72 20 74 6f 20 70 65 65 72 } //Set up peer to peer  1
		$a_80_4 = {53 61 76 65 64 20 74 61 73 6b 20 66 72 6f 6d 20 70 65 65 72 } //Saved task from peer  1
		$a_80_5 = {53 61 76 65 64 20 74 61 73 6b 20 66 72 6f 6d 20 43 32 20 73 65 72 76 65 72 } //Saved task from C2 server  1
		$a_80_6 = {53 61 76 69 6e 67 20 70 61 79 6c 6f 61 64 20 74 6f } //Saving payload to  1
		$a_80_7 = {2f 6a 61 76 61 73 63 72 69 70 74 2f 76 69 65 77 2e 70 68 70 } ///javascript/view.php  1
		$a_80_8 = {5b 57 41 52 4e 2d 49 4e 4a 5d 20 52 65 69 6e 6a 65 63 74 69 6e 67 20 64 75 65 20 74 6f 20 65 72 72 6f 72 2c 20 73 65 65 20 65 72 72 6f 72 20 6c 6f 67 } //[WARN-INJ] Reinjecting due to error, see error log  1
		$a_80_9 = {5b 57 41 52 4e 2d 49 4e 4a 5d 20 47 65 74 50 72 6f 63 65 73 73 56 65 63 74 6f 72 73 48 61 6e 64 6c 65 50 49 44 73 50 50 49 44 73 20 66 61 69 6c 65 64 20 66 6f 72 20 70 72 6f 63 65 73 73 20 } //[WARN-INJ] GetProcessVectorsHandlePIDsPPIDs failed for process   1
		$a_80_10 = {5b 57 41 52 4e 2d 54 41 53 4b 5d 20 55 6e 61 62 6c 65 20 74 6f 20 62 75 69 6c 64 20 74 61 73 6b 20 66 72 6f 6d 20 6c 69 6e 65 2c 20 65 72 72 6f 72 3a 20 } //[WARN-TASK] Unable to build task from line, error:   1
		$a_80_11 = {5b 54 41 53 4b 5d 20 54 61 73 6b 20 73 75 63 63 65 73 73 66 75 6c 6c 79 20 62 75 69 6c 74 } //[TASK] Task successfully built  1
		$a_80_12 = {5b 54 41 53 4b 5d 20 54 61 73 6b 20 63 6f 6e 66 69 67 3a } //[TASK] Task config:  1
		$a_80_13 = {5b 54 41 53 4b 5d 20 52 65 6c 65 61 73 69 6e 67 20 6d 75 74 65 78 2c 20 73 6c 65 65 70 69 6e 67 2e 2e 2e } //[TASK] Releasing mutex, sleeping...  1
		$a_80_14 = {5b 54 41 53 4b 5d 20 52 65 63 69 65 76 65 64 20 74 61 73 6b 20 6c 69 6e 65 3a 20 } //[TASK] Recieved task line:   1
		$a_80_15 = {5b 54 41 53 4b 5d 20 50 61 79 6c 6f 61 64 20 66 69 6c 65 70 61 74 68 3a 20 } //[TASK] Payload filepath:   1
		$a_80_16 = {5b 54 41 53 4b 5d 20 4f 72 63 68 65 73 74 72 61 74 6f 72 20 74 61 73 6b 20 66 69 6c 65 20 73 69 7a 65 3a 20 } //[TASK] Orchestrator task file size:   1
		$a_80_17 = {5b 54 41 53 4b 5d 20 43 6f 6d 6d 73 20 6c 69 62 20 69 6e 61 63 74 69 76 65 2c 20 73 6c 65 65 70 69 6e 67 } //[TASK] Comms lib inactive, sleeping  1
		$a_80_18 = {5b 54 41 53 4b 5d 20 41 74 74 65 6d 70 74 69 6e 67 20 74 6f 20 67 65 74 20 6f 77 6e 65 72 73 68 69 70 20 6f 66 20 6d 75 74 65 78 3a 20 } //[TASK] Attempting to get ownership of mutex:   1
		$a_80_19 = {5b 4f 52 43 48 5d 20 53 65 6e 64 20 66 69 6c 65 20 70 61 74 68 3a 20 } //[ORCH] Send file path:   1
		$a_80_20 = {5b 4f 52 43 48 5d 20 43 6f 6e 66 69 67 20 63 6f 6e 74 65 6e 74 73 3a } //[ORCH] Config contents:  1
		$a_80_21 = {5b 4d 54 58 5d 20 53 75 63 63 65 73 73 66 75 6c 6c 79 20 63 72 65 61 74 65 64 20 6d 75 74 65 78 65 73 } //[MTX] Successfully created mutexes  1
		$a_80_22 = {5b 4d 41 49 4e 5d 20 53 74 61 72 74 69 6e 67 20 69 6e 6a 65 63 74 69 6f 6e 20 6c 6f 6f 70 } //[MAIN] Starting injection loop  1
		$a_80_23 = {5b 49 4e 4a 5d 20 41 74 74 65 6d 70 74 69 6e 67 20 74 6f 20 69 6e 6a 65 63 74 20 69 6e 74 6f 20 } //[INJ] Attempting to inject into   1
		$a_80_24 = {5b 45 52 52 4f 52 2d 54 41 53 4b 5d 20 54 61 73 6b 69 6e 67 20 52 65 61 64 54 61 73 6b 46 69 6c 65 20 65 6e 63 6f 75 6e 74 65 72 65 64 20 65 72 72 6f 72 20 72 65 61 64 69 6e 67 20 74 61 73 6b 20 66 69 6c 65 20 } //[ERROR-TASK] Tasking ReadTaskFile encountered error reading task file   1
		$a_80_25 = {5b 45 52 52 4f 52 2d 54 41 53 4b 5d 20 43 72 65 61 74 65 50 72 6f 63 65 73 73 41 20 66 61 69 6c 65 64 2e 20 47 65 74 4c 61 73 74 45 72 72 6f 72 3a 20 } //[ERROR-TASK] CreateProcessA failed. GetLastError:   1
		$a_80_26 = {5b 45 52 52 4f 52 2d 49 4e 4a 5d 20 74 61 72 67 65 74 50 72 6f 63 65 73 73 65 73 20 69 73 20 65 6d 70 74 79 20 61 66 74 65 72 20 61 74 74 65 6d 70 74 69 6e 67 20 74 6f 20 62 75 69 6c 64 20 76 65 63 74 6f 72 2e } //[ERROR-INJ] targetProcesses is empty after attempting to build vector.  1
		$a_80_27 = {5b 45 52 52 4f 52 2d 49 4e 4a 5d 20 74 61 72 67 65 74 50 72 6f 63 4c 69 73 74 20 69 73 20 65 6d 70 74 79 20 61 66 74 65 72 20 47 65 74 43 6f 6e 66 69 67 56 61 6c 75 65 20 63 61 6c 6c 2e } //[ERROR-INJ] targetProcList is empty after GetConfigValue call.  1
		$a_80_28 = {5b 45 52 52 4f 52 2d 49 4e 4a 5d 20 57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 20 66 61 69 6c 65 64 2e 20 47 65 74 4c 61 73 74 45 72 72 6f 72 3a 20 } //[ERROR-INJ] WriteProcessMemory failed. GetLastError:   1
		$a_80_29 = {5b 45 52 52 4f 52 2d 49 4e 4a 5d 20 55 6e 61 62 6c 65 20 74 6f 20 6c 6f 63 61 74 65 20 44 4c 4c 20 74 6f 20 69 6e 6a 65 63 74 20 61 74 20 70 61 74 68 3a 20 } //[ERROR-INJ] Unable to locate DLL to inject at path:   1
		$a_80_30 = {5b 45 52 52 4f 52 2d 49 4e 4a 5d 20 53 6e 61 70 73 68 6f 74 20 65 6d 70 74 79 20 6f 72 20 69 73 73 75 65 20 77 69 74 68 20 50 72 6f 63 65 73 73 33 32 46 69 72 73 74 2e 20 47 65 74 4c 61 73 74 45 72 72 6f 72 3a 20 } //[ERROR-INJ] Snapshot empty or issue with Process32First. GetLastError:   1
		$a_80_31 = {5b 45 52 52 4f 52 2d 49 4e 4a 5d 20 50 65 72 66 6f 72 6d 49 6e 6a 65 63 74 69 6f 6e 20 66 61 69 6c 65 64 20 66 6f 72 20 70 72 6f 63 65 73 73 20 } //[ERROR-INJ] PerformInjection failed for process   1
		$a_80_32 = {5b 45 52 52 4f 52 2d 49 4e 4a 5d 20 49 6e 6a 65 63 74 69 6f 6e 4d 61 69 6e 20 66 61 69 6c 65 64 20 77 69 74 68 20 65 72 72 6f 72 20 63 6f 64 65 3a 20 } //[ERROR-INJ] InjectionMain failed with error code:   1
		$a_80_33 = {5b 45 52 52 4f 52 2d 49 4e 4a 5d 20 43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 20 66 61 69 6c 65 64 2e 20 47 65 74 4c 61 73 74 45 72 72 6f 72 3a 20 } //[ERROR-INJ] CreateToolhelp32Snapshot failed. GetLastError:   1
		$a_80_34 = {5b 45 52 52 4f 52 2d 49 4e 4a 5d 20 41 64 6a 75 73 74 54 6f 6b 65 6e 50 72 69 76 69 6c 65 67 65 73 20 66 61 69 6c 65 64 2e 20 52 65 74 75 72 6e 56 61 6c 75 65 3a 20 } //[ERROR-INJ] AdjustTokenPrivileges failed. ReturnValue:   1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_80_8  & 1)*1+(#a_80_9  & 1)*1+(#a_80_10  & 1)*1+(#a_80_11  & 1)*1+(#a_80_12  & 1)*1+(#a_80_13  & 1)*1+(#a_80_14  & 1)*1+(#a_80_15  & 1)*1+(#a_80_16  & 1)*1+(#a_80_17  & 1)*1+(#a_80_18  & 1)*1+(#a_80_19  & 1)*1+(#a_80_20  & 1)*1+(#a_80_21  & 1)*1+(#a_80_22  & 1)*1+(#a_80_23  & 1)*1+(#a_80_24  & 1)*1+(#a_80_25  & 1)*1+(#a_80_26  & 1)*1+(#a_80_27  & 1)*1+(#a_80_28  & 1)*1+(#a_80_29  & 1)*1+(#a_80_30  & 1)*1+(#a_80_31  & 1)*1+(#a_80_32  & 1)*1+(#a_80_33  & 1)*1+(#a_80_34  & 1)*1) >=35
 
}