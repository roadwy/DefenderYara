
rule Trojan_BAT_Nanocore_LTD_MTB{
	meta:
		description = "Trojan:BAT/Nanocore.LTD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {0a 16 0b 38 21 00 00 00 7e 30 00 00 04 07 9a 06 28 90 01 03 0a 39 0b 00 00 00 7e 31 00 00 04 74 19 00 00 01 2a 07 17 58 0b 07 7e 30 00 00 04 8e 69 3f d2 ff ff ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}