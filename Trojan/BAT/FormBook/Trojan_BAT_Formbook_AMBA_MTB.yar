
rule Trojan_BAT_Formbook_AMBA_MTB{
	meta:
		description = "Trojan:BAT/Formbook.AMBA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {07 11 09 11 0f 11 07 5d d2 9c } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_Formbook_AMBA_MTB_2{
	meta:
		description = "Trojan:BAT/Formbook.AMBA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {03 04 61 05 59 20 90 01 02 00 00 58 90 00 } //01 00 
		$a_03_1 = {02 03 61 04 59 20 90 01 02 00 00 58 90 00 } //01 00 
		$a_01_2 = {11 0e 08 11 08 1f 16 5d 91 61 13 0f } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_Formbook_AMBA_MTB_3{
	meta:
		description = "Trojan:BAT/Formbook.AMBA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {38 00 30 00 34 00 31 00 33 00 30 00 30 00 43 00 42 00 30 00 39 00 41 00 44 00 30 00 34 00 31 00 31 00 30 00 30 00 43 00 30 00 30 00 41 00 32 00 34 00 30 00 35 00 31 00 33 00 30 00 31 00 43 00 41 00 30 00 41 00 32 00 37 00 30 00 35 00 31 00 33 00 30 00 31 00 44 00 45 00 30 00 41 00 32 00 42 00 30 00 35 00 31 00 33 00 30 00 31 00 5a 00 32 00 30 00 41 00 32 } //01 00 
		$a_01_1 = {36 00 30 00 42 00 33 00 33 00 30 00 35 00 31 00 33 00 30 00 31 00 31 00 41 00 30 00 42 00 33 00 37 00 30 00 35 00 31 00 33 00 30 00 31 00 32 00 45 00 30 00 42 00 33 00 33 00 30 00 35 00 31 00 33 00 30 00 31 00 34 00 32 00 30 00 42 00 33 00 42 00 30 00 35 00 31 00 33 00 30 00 31 00 35 00 36 00 30 00 42 00 33 00 } //01 00  60B330513011A0B370513012E0B33051301420B3B051301560B3
		$a_03_2 = {07 08 18 5b 02 08 18 6f 90 01 01 00 00 0a 1f 10 28 90 01 01 00 00 0a 9c 00 08 18 58 0c 08 06 fe 04 0d 09 2d de 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}