
rule Trojan_BAT_Small_FB_MTB{
	meta:
		description = "Trojan:BAT/Small.FB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 03 00 00 0a 00 "
		
	strings :
		$a_00_0 = {20 00 ca 9a 3b 0d 16 13 04 2b 50 00 1f 2d 28 1a 00 00 0a 00 16 13 05 2b 2e 00 07 11 05 06 08 06 6f 1b 00 00 0a 6f 1c 00 00 0a 6f 1d 00 00 0a 9d 07 73 1e 00 00 0a 13 06 11 06 28 1f 00 00 0a 00 00 11 05 17 58 13 05 11 05 07 8e 69 fe 04 13 07 11 07 2d c5 } //03 00 
		$a_81_1 = {4c 6f 61 64 65 72 } //03 00  Loader
		$a_81_2 = {43 68 65 61 74 } //00 00  Cheat
	condition:
		any of ($a_*)
 
}