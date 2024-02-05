
rule Trojan_BAT_Nanocore_ABHB_MTB{
	meta:
		description = "Trojan:BAT/Nanocore.ABHB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {08 11 09 72 90 01 03 70 28 90 01 03 0a 72 90 01 03 70 20 90 01 03 00 14 14 18 8d 90 01 03 01 25 16 07 11 09 9a a2 25 17 1f 10 8c 90 01 03 01 a2 6f 90 01 03 0a a5 90 01 03 01 9c 11 09 17 58 13 09 11 09 07 8e 69 fe 04 13 0a 11 0a 2d b2 90 00 } //01 00 
		$a_01_1 = {41 00 70 00 70 00 2e 00 41 00 70 00 6c 00 69 00 63 00 61 00 74 00 74 00 69 00 6f 00 6e 00 2e 00 52 00 65 00 43 00 53 00 } //00 00 
	condition:
		any of ($a_*)
 
}