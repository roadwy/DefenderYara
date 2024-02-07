
rule Trojan_BAT_Heracles_NBH_MTB{
	meta:
		description = "Trojan:BAT/Heracles.NBH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 05 00 "
		
	strings :
		$a_03_0 = {12 02 fe 16 13 00 00 02 6f 90 01 03 0a 7e 90 01 03 04 28 90 01 03 06 73 90 01 03 0a 7a 11 01 1a 9a a5 90 01 03 01 13 00 38 90 01 03 ff 11 07 1f 13 58 90 00 } //01 00 
		$a_01_1 = {55 79 64 77 74 6d 74 79 63 6b 79 62 6a 77 63 6b 79 6f } //01 00  Uydwtmtyckybjwckyo
		$a_01_2 = {50 72 6f 63 65 73 73 57 69 6e 64 6f 77 53 74 79 6c 65 } //00 00  ProcessWindowStyle
	condition:
		any of ($a_*)
 
}