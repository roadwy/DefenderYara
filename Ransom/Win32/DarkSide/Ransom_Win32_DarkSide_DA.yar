
rule Ransom_Win32_DarkSide_DA{
	meta:
		description = "Ransom:Win32/DarkSide.DA,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {89 54 0e 0c 89 44 0e 08 89 5c 0e 04 89 3c 0e 81 ea 10 10 10 10 2d 10 10 10 10 81 eb 10 10 10 10 81 ef 10 10 10 10 } //01 00 
		$a_03_1 = {02 14 1e 02 d0 8a 90 01 04 00 43 88 90 01 04 00 88 90 01 04 00 3b df 73 06 fe c1 75 da eb 06 33 db fe c1 75 d2 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}