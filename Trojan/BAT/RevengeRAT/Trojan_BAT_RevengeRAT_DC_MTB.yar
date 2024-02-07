
rule Trojan_BAT_RevengeRAT_DC_MTB{
	meta:
		description = "Trojan:BAT/RevengeRAT.DC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 0a 00 "
		
	strings :
		$a_02_0 = {0a 1e 5b 8d 2a 00 00 01 0b 16 0d 2b 19 00 07 09 06 09 1e 5a 1e 6f 90 01 03 0a 18 28 90 01 03 0a 9c 00 09 17 58 0d 09 07 8e 69 17 59 fe 02 16 fe 01 13 04 11 04 2d d6 90 00 } //01 00 
		$a_81_1 = {52 65 70 6c 61 63 65 } //01 00  Replace
		$a_81_2 = {54 6f 42 79 74 65 } //01 00  ToByte
		$a_81_3 = {43 6f 6e 76 65 72 74 } //00 00  Convert
	condition:
		any of ($a_*)
 
}