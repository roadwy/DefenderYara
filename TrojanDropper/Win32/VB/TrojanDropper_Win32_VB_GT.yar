
rule TrojanDropper_Win32_VB_GT{
	meta:
		description = "TrojanDropper:Win32/VB.GT,SIGNATURE_TYPE_PEHSTR_EXT,20 00 20 00 06 00 00 0a 00 "
		
	strings :
		$a_01_0 = {6e 68 61 61 6c 63 6c 6b 69 65 6d 72 } //0a 00  nhaalclkiemr
		$a_01_1 = {49 41 6c 67 6f 72 69 74 68 6d 5f 44 65 63 72 79 70 74 53 74 72 69 6e 67 } //01 00  IAlgorithm_DecryptString
		$a_00_2 = {74 00 61 00 73 00 6b 00 6b 00 69 00 6c 00 6c 00 20 00 2f 00 46 00 20 00 2f 00 49 00 4d 00 } //01 00  taskkill /F /IM
		$a_00_3 = {63 00 6d 00 64 00 20 00 2f 00 43 00 20 00 00 00 08 00 00 00 74 00 65 00 6d 00 70 00 } //01 00 
		$a_01_4 = {2f 00 76 00 20 00 44 00 6f 00 4e 00 6f 00 74 00 41 00 6c 00 6c 00 6f 00 77 00 45 00 78 00 63 00 65 00 70 00 74 00 69 00 6f 00 6e 00 73 00 20 00 2f 00 74 00 20 00 52 00 45 00 47 00 5f 00 44 00 57 00 4f 00 52 00 44 00 20 00 2f 00 64 00 20 00 30 00 20 00 2f 00 66 00 } //0a 00  /v DoNotAllowExceptions /t REG_DWORD /d 0 /f
		$a_00_5 = {4d 53 56 42 56 4d 36 30 2e 44 4c 4c } //00 00  MSVBVM60.DLL
	condition:
		any of ($a_*)
 
}