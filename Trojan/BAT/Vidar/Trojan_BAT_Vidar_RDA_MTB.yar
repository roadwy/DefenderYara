
rule Trojan_BAT_Vidar_RDA_MTB{
	meta:
		description = "Trojan:BAT/Vidar.RDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {64 36 37 32 65 66 30 64 2d 39 35 62 32 2d 34 34 39 30 2d 38 39 62 38 2d 37 38 39 61 39 33 39 64 66 61 64 32 } //02 00 
		$a_01_1 = {11 0c 11 0f 1f 0f 5f 11 0c 11 0f 1f 0f 5f 95 11 05 25 1a 58 13 05 4b 61 } //00 00 
	condition:
		any of ($a_*)
 
}