
rule Trojan_BAT_Redline_GFM_MTB{
	meta:
		description = "Trojan:BAT/Redline.GFM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 0a 00 "
		
	strings :
		$a_03_0 = {08 8d 4f 00 00 01 13 04 7e 8f 01 00 04 02 1a 58 11 04 16 08 28 90 01 03 0a 28 90 01 03 0a 11 04 16 11 04 8e 69 6f 90 01 03 0a 13 05 7e 7f 01 00 04 11 05 90 00 } //01 00 
		$a_01_1 = {45 35 55 75 4c 6c 4c 76 6f 70 } //01 00 
		$a_01_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00 
		$a_01_3 = {43 72 65 61 74 65 45 6e 63 72 79 70 74 6f 72 } //00 00 
	condition:
		any of ($a_*)
 
}