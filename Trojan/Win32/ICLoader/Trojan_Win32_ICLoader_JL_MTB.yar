
rule Trojan_Win32_ICLoader_JL_MTB{
	meta:
		description = "Trojan:Win32/ICLoader.JL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 07 00 00 06 00 "
		
	strings :
		$a_01_0 = {8b 55 fc 8a 04 1a 32 04 0e 32 c1 42 83 fa 0f 89 55 fc 76 09 81 e2 00 01 00 00 89 55 fc 88 04 0e 41 3b cf 72 db } //01 00 
		$a_01_1 = {4e 65 74 77 6f 72 6b 4d 69 6e 65 72 } //01 00 
		$a_01_2 = {57 69 72 65 73 68 61 72 6b } //01 00 
		$a_01_3 = {72 6f 78 69 66 69 65 72 } //01 00 
		$a_01_4 = {48 54 54 50 20 41 6e 61 6c 79 7a 65 72 } //01 00 
		$a_01_5 = {2f 63 20 74 61 73 6b 6b 69 6c 6c 20 2f 69 6d } //01 00 
		$a_01_6 = {2f 66 20 26 20 65 72 61 73 65 } //00 00 
	condition:
		any of ($a_*)
 
}