
rule Backdoor_Win32_Farfli_B{
	meta:
		description = "Backdoor:Win32/Farfli.B,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 44 24 08 56 8b f1 89 06 8b 44 24 08 85 c0 74 02 ff d0 } //01 00 
		$a_01_1 = {f3 a5 8b cd 83 e1 03 85 d2 f3 a4 } //01 00 
		$a_01_2 = {8b 74 24 0c 57 56 ff 96 68 01 00 00 8b f8 8d 46 20 50 ff 96 68 01 00 00 8d 4e 60 8b d8 51 ff 96 68 01 } //01 00 
		$a_01_3 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //01 00  WriteProcessMemory
		$a_01_4 = {43 72 65 61 74 65 52 65 6d 6f 74 65 54 68 72 65 61 64 } //01 00  CreateRemoteThread
		$a_01_5 = {46 08 89 06 f7 d8 1b c0 25 05 01 00 00 89 46 04 46 } //01 00 
		$a_01_6 = {66 c7 44 24 18 58 02 89 4c 24 14 } //00 00 
	condition:
		any of ($a_*)
 
}