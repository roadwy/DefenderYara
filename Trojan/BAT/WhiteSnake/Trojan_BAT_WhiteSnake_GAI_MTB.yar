
rule Trojan_BAT_WhiteSnake_GAI_MTB{
	meta:
		description = "Trojan:BAT/WhiteSnake.GAI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 03 00 "
		
	strings :
		$a_03_0 = {11 0d 9e 06 06 08 94 06 09 94 58 20 00 01 00 00 5d 94 13 0e 11 04 11 0c 02 11 0c 91 11 0e 61 28 90 01 01 00 00 0a 9c 00 11 0c 17 58 13 0c 11 0c 02 8e 69 fe 04 13 0f 11 0f 3a 90 00 } //02 00 
		$a_01_1 = {70 00 6f 00 72 00 6e 00 68 00 75 00 62 00 2e 00 63 00 6f 00 6d 00 } //00 00  pornhub.com
	condition:
		any of ($a_*)
 
}