
rule Trojan_BAT_XWormRAT_Y_MTB{
	meta:
		description = "Trojan:BAT/XWormRAT.Y!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {0a 11 03 11 03 18 5a 7e 90 01 02 00 04 28 90 01 02 00 06 6c 7e 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}