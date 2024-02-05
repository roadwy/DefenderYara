
rule Trojan_BAT_Cerbu_AMAA_MTB{
	meta:
		description = "Trojan:BAT/Cerbu.AMAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {11 06 11 07 11 05 11 07 28 90 01 02 00 06 20 90 01 02 00 00 61 d1 9d 20 90 01 01 00 00 00 28 90 01 02 00 06 13 0c 2b a7 90 00 } //05 00 
		$a_01_1 = {06 07 06 07 93 1f 66 61 02 61 d1 9d 2b 12 07 17 59 25 0b 16 2f ea } //00 00 
	condition:
		any of ($a_*)
 
}