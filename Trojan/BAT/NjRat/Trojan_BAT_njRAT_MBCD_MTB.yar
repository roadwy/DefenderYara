
rule Trojan_BAT_njRAT_MBCD_MTB{
	meta:
		description = "Trojan:BAT/njRAT.MBCD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {0a 08 16 73 90 01 01 00 00 0a 13 05 11 05 09 16 09 8e b7 6f 3d 00 00 0a 26 de 0c 90 00 } //01 00 
		$a_01_1 = {61 64 30 61 39 30 66 30 2d 61 64 35 38 2d 34 65 35 62 2d 38 35 37 37 2d 31 34 63 66 34 37 30 33 64 33 64 33 } //00 00 
	condition:
		any of ($a_*)
 
}