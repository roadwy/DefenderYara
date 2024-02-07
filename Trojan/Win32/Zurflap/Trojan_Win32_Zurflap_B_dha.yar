
rule Trojan_Win32_Zurflap_B_dha{
	meta:
		description = "Trojan:Win32/Zurflap.B!dha,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 0a 00 00 02 00 "
		
	strings :
		$a_00_0 = {52 75 6e 52 75 6e 45 76 65 6e 74 } //02 00  RunRunEvent
		$a_00_1 = {44 65 6c 44 65 6c 4d 75 74 65 78 } //02 00  DelDelMutex
		$a_01_2 = {2e 3f 41 56 43 4d 65 6d 4c 6f 61 64 44 6c 6c 40 40 } //02 00  .?AVCMemLoadDll@@
		$a_01_3 = {49 46 69 72 73 74 44 6c 6c 2e 64 6c 6c } //02 00  IFirstDll.dll
		$a_01_4 = {9f 2e fe 6e 6e 99 89 48 ec 6c 6c aa } //01 00 
		$a_01_5 = {4d 69 63 72 6f 73 6f 66 74 5c 50 72 6f 74 65 63 74 5c 64 75 6d 70 63 68 6b 2e 65 78 65 } //01 00  Microsoft\Protect\dumpchk.exe
		$a_01_6 = {4d 69 63 72 6f 73 6f 66 74 5c 50 72 6f 74 65 63 74 5c 64 62 67 65 6e 67 2e 64 6c 6c } //01 00  Microsoft\Protect\dbgeng.dll
		$a_01_7 = {53 79 73 57 4f 57 36 34 5c 78 70 73 72 63 68 76 77 2e 65 78 65 } //01 00  SysWOW64\xpsrchvw.exe
		$a_01_8 = {7e 44 46 46 45 4f 34 43 2e 54 4d 50 } //01 00  ~DFFEO4C.TMP
		$a_01_9 = {49 43 6c 69 65 6e 74 44 6c 6c 2e 64 6c 6c } //00 00  IClientDll.dll
	condition:
		any of ($a_*)
 
}