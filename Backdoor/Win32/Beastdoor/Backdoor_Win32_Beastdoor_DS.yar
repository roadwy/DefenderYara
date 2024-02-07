
rule Backdoor_Win32_Beastdoor_DS{
	meta:
		description = "Backdoor:Win32/Beastdoor.DS,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 05 00 00 03 00 "
		
	strings :
		$a_01_0 = {3d 3d 3d 3d 3d 20 53 68 75 74 20 44 6f 77 6e 3a 5b } //03 00  ===== Shut Down:[
		$a_01_1 = {43 68 61 74 20 73 65 73 73 69 6f 6e 20 73 74 61 72 74 65 64 20 62 79 } //01 00  Chat session started by
		$a_01_2 = {5c 70 6f 6c 69 63 69 65 73 5c 45 78 70 6c 6f 72 65 72 5c 52 75 6e } //01 00  \policies\Explorer\Run
		$a_01_3 = {53 77 61 70 4d 6f 75 73 65 42 75 74 74 6f 6e } //01 00  SwapMouseButton
		$a_01_4 = {54 6f 6f 6c 68 65 6c 70 33 32 52 65 61 64 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //00 00  Toolhelp32ReadProcessMemory
	condition:
		any of ($a_*)
 
}