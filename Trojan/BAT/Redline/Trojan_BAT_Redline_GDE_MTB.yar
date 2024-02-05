
rule Trojan_BAT_Redline_GDE_MTB{
	meta:
		description = "Trojan:BAT/Redline.GDE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 0a 00 "
		
	strings :
		$a_03_0 = {08 11 07 07 11 07 9a 1f 10 28 90 01 03 0a 9c 11 07 17 58 13 07 11 07 07 8e 69 fe 04 13 08 11 08 90 00 } //01 00 
		$a_01_1 = {39 38 61 34 32 61 31 35 2d 63 31 36 65 2d 34 35 63 65 2d 62 34 62 63 2d 63 30 35 64 30 34 65 38 32 66 31 66 } //01 00 
		$a_01_2 = {67 65 74 5f 49 73 48 69 64 64 65 6e } //00 00 
	condition:
		any of ($a_*)
 
}