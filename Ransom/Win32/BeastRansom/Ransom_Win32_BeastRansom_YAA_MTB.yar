
rule Ransom_Win32_BeastRansom_YAA_MTB{
	meta:
		description = "Ransom:Win32/BeastRansom.YAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {17 10 14 06 8b c3 c7 44 24 90 01 01 01 75 1d 10 c7 44 24 90 01 01 07 10 6a 00 80 74 04 90 00 } //0a 00 
		$a_03_1 = {03 ca 33 d9 c1 c3 10 03 c3 89 45 90 01 01 33 c2 8b 55 90 01 01 c1 c0 0c 03 d6 03 c8 33 d9 89 4d ac 90 00 } //00 00 
		$a_00_2 = {5d 04 00 00 72 31 06 80 5c 2f } //00 00 
	condition:
		any of ($a_*)
 
}