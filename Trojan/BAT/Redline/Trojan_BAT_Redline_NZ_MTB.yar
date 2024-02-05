
rule Trojan_BAT_Redline_NZ_MTB{
	meta:
		description = "Trojan:BAT/Redline.NZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 0a 00 "
		
	strings :
		$a_03_0 = {09 08 09 08 6f 90 01 03 0a 5d 6f 90 01 03 0a 02 7b 90 01 03 04 09 91 61 d2 9c 00 09 17 58 0d 09 02 7b 90 01 03 04 8e 69 fe 04 13 04 11 04 2d c9 90 00 } //01 00 
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00 
		$a_01_2 = {49 6e 76 6f 6b 65 } //00 00 
	condition:
		any of ($a_*)
 
}