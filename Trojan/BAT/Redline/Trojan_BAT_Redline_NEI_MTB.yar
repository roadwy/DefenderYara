
rule Trojan_BAT_Redline_NEI_MTB{
	meta:
		description = "Trojan:BAT/Redline.NEI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {02 03 02 4b 03 04 61 05 61 58 0e 07 0e 04 e0 95 58 7e 2a 01 00 04 0e 06 17 59 e0 95 58 0e 05 28 46 05 00 06 58 54 2a } //01 00 
		$a_01_1 = {54 00 52 00 65 00 70 00 6c 00 61 00 63 00 65 00 6f 00 6b 00 52 00 65 00 70 00 6c 00 61 00 63 00 65 00 65 00 6e 00 52 00 65 00 70 00 6c 00 61 00 63 00 65 00 73 00 2e 00 74 00 52 00 65 00 70 00 6c 00 61 00 63 00 65 00 78 00 } //00 00  TReplaceokReplaceenReplaces.tReplacex
	condition:
		any of ($a_*)
 
}