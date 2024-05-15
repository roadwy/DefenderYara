
rule Ransom_Win32_Beast_YAA_MTB{
	meta:
		description = "Ransom:Win32/Beast.YAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {80 74 04 0c 55 40 83 f8 0b 72 f5 } //01 00 
		$a_03_1 = {0b c8 8b 45 ec 31 4d 90 01 01 23 45 90 01 01 8b 4d 90 01 01 f7 d1 23 4d e0 33 c8 90 00 } //00 00 
		$a_00_2 = {5d } //04 00  ]
	condition:
		any of ($a_*)
 
}