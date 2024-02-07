
rule Trojan_Win32_Darkeye_MA_MTB{
	meta:
		description = "Trojan:Win32/Darkeye.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {1c 36 32 b6 a4 f3 8c 42 b7 43 08 7c 79 1d 30 6a } //01 00 
		$a_01_1 = {34 43 33 65 6e 6d 65 73 68 } //01 00  4C3enmesh
		$a_01_2 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //01 00  WriteProcessMemory
		$a_01_3 = {44 65 6d 6f 6e 69 73 6d 73 } //01 00  Demonisms
		$a_01_4 = {62 00 61 00 72 00 62 00 61 00 74 00 69 00 66 00 20 00 6c 00 65 00 63 00 74 00 72 00 69 00 66 00 69 00 65 00 72 00 6f 00 6e 00 73 00 } //00 00  barbatif lectrifierons
	condition:
		any of ($a_*)
 
}