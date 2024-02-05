
rule Trojan_BAT_Redline_GEH_MTB{
	meta:
		description = "Trojan:BAT/Redline.GEH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 0a 00 "
		
	strings :
		$a_03_0 = {04 06 18 28 90 01 03 06 16 2d f1 7e 90 01 04 06 28 90 01 03 06 0d 7e 90 01 04 09 03 16 03 8e 69 28 90 01 03 06 13 04 1e 90 00 } //01 00 
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //01 00 
		$a_01_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00 
		$a_01_3 = {52 69 6a 6e 64 61 65 6c 4d 61 6e 61 67 65 64 } //00 00 
	condition:
		any of ($a_*)
 
}