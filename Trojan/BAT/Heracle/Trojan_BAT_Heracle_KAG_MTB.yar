
rule Trojan_BAT_Heracle_KAG_MTB{
	meta:
		description = "Trojan:BAT/Heracle.KAG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {25 2b 06 20 90 01 04 25 26 08 20 90 01 04 5a 61 2b a4 07 16 31 08 90 00 } //01 00 
		$a_01_1 = {6b 67 77 75 72 68 6d 61 6a 6b 64 6f 65 7a 70 } //00 00  kgwurhmajkdoezp
	condition:
		any of ($a_*)
 
}