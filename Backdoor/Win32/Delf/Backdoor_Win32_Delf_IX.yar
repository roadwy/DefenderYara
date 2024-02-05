
rule Backdoor_Win32_Delf_IX{
	meta:
		description = "Backdoor:Win32/Delf.IX,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {ff ff ff ff 12 00 00 00 64 65 6c 20 2e 5c 64 65 6c 6d 65 65 78 65 2e 62 61 74 00 } //01 00 
		$a_03_1 = {8d 43 20 b1 45 ba e8 fd 00 00 e8 90 01 04 0f b7 17 90 00 } //01 00 
		$a_03_2 = {89 43 04 8b 45 14 e8 90 01 04 66 83 c0 1c 66 89 07 66 b8 04 00 66 c7 45 90 01 01 05 00 c1 e0 04 0a 45 90 01 01 88 45 90 01 01 c6 45 90 01 01 00 66 8b 07 50 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}