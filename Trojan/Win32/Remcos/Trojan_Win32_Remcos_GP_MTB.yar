
rule Trojan_Win32_Remcos_GP_MTB{
	meta:
		description = "Trojan:Win32/Remcos.GP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b d0 03 d2 8b 4c 24 08 8d 54 d1 04 89 54 24 04 8b 54 24 04 8b 0b 89 0a 8b 54 24 04 89 13 40 83 f8 64 } //01 00 
		$a_01_1 = {44 00 56 00 43 00 4c 00 41 00 4c } //01 00 
		$a_01_2 = {4e 00 4f 00 4d 00 53 00 49 00 4c } //01 00 
		$a_81_3 = {52 54 4c 43 6f 6e 73 74 73 } //01 00 
		$a_81_4 = {47 65 74 43 6c 69 70 62 6f 61 72 64 44 61 74 61 } //01 00 
		$a_81_5 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //00 00 
	condition:
		any of ($a_*)
 
}