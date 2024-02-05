
rule Trojan_BAT_XWormRAT_G_MTB{
	meta:
		description = "Trojan:BAT/XWormRAT.G!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {08 11 04 16 73 90 01 02 00 0a 0d 09 07 6f 90 01 02 00 0a 7e 90 01 01 00 00 04 07 6f 90 01 02 00 0a 14 6f 90 00 } //02 00 
		$a_01_1 = {20 00 01 00 00 14 14 14 6f } //00 00 
	condition:
		any of ($a_*)
 
}