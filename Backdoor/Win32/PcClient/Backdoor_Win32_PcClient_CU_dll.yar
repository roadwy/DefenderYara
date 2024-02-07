
rule Backdoor_Win32_PcClient_CU_dll{
	meta:
		description = "Backdoor:Win32/PcClient.CU!dll,SIGNATURE_TYPE_PEHSTR_EXT,31 00 31 00 07 00 00 03 00 "
		
	strings :
		$a_03_0 = {32 30 30 20 25 73 25 73 25 73 00 90 02 30 3e 20 6e 75 6c 00 90 02 30 43 4f 4d 53 50 45 43 90 00 } //03 00 
		$a_01_1 = {67 6f 6f 67 31 65 2e } //03 00  goog1e.
		$a_01_2 = {68 74 74 70 3a 2f 2f 25 73 3a 25 64 2f 25 73 25 64 25 30 38 64 } //03 00  http://%s:%d/%s%d%08d
		$a_01_3 = {69 6e 64 65 78 2e 61 73 70 3f } //03 00  index.asp?
		$a_03_4 = {5c 53 79 73 74 65 6d 33 32 5c 64 72 69 76 65 72 73 5c 90 02 10 2e 73 79 73 00 90 00 } //14 00 
		$a_01_5 = {43 72 65 61 74 65 52 65 6d 6f 74 65 54 68 72 65 61 64 } //14 00  CreateRemoteThread
		$a_01_6 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //00 00  WriteProcessMemory
	condition:
		any of ($a_*)
 
}