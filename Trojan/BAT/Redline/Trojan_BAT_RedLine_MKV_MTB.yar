
rule Trojan_BAT_RedLine_MKV_MTB{
	meta:
		description = "Trojan:BAT/RedLine.MKV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {06 11 04 06 8e 69 5d 06 11 04 06 8e 69 5d 91 07 11 04 1f 16 5d 91 61 28 90 01 03 0a 06 11 04 17 58 06 8e 69 5d 91 28 90 01 03 0a 59 20 90 01 03 00 58 20 00 01 00 00 5d d2 9c 00 11 04 15 58 13 04 11 04 16 fe 04 16 fe 01 13 05 11 05 2d b0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}