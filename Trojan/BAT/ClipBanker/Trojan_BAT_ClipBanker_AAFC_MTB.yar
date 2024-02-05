
rule Trojan_BAT_ClipBanker_AAFC_MTB{
	meta:
		description = "Trojan:BAT/ClipBanker.AAFC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 04 00 "
		
	strings :
		$a_03_0 = {0b 06 16 fe 0e 03 00 20 f8 ff ff ff 20 5d 3c 3f 74 20 8e ff 6d 1f 61 20 d3 c3 52 6b 40 90 01 01 00 00 00 20 02 00 00 00 fe 0e 03 00 fe 90 01 02 00 00 01 58 00 73 90 01 01 00 00 0a 0c 08 07 6f 90 01 01 00 00 0a 08 6f 90 01 01 00 00 0a 07 6f 90 01 01 00 00 0a 06 6f 90 01 01 00 00 0a 07 6f 90 01 01 00 00 0a 2a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}