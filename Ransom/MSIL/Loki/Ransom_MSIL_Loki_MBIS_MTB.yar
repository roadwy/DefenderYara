
rule Ransom_MSIL_Loki_MBIS_MTB{
	meta:
		description = "Ransom:MSIL/Loki.MBIS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {11 18 11 19 11 1a 28 90 01 01 00 00 06 13 1b 07 11 16 11 1b 20 00 01 00 00 5d d2 9c 00 11 15 17 59 13 15 11 15 16 fe 04 16 fe 01 13 1c 11 1c 2d a9 90 00 } //01 00 
		$a_01_1 = {38 00 38 00 34 00 35 00 55 00 53 00 42 00 34 00 5a 00 35 00 35 00 34 00 49 00 48 00 59 00 46 00 37 00 34 00 59 00 49 00 44 00 41 00 } //00 00 
	condition:
		any of ($a_*)
 
}