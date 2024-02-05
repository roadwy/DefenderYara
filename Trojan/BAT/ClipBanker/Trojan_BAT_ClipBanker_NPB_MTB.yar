
rule Trojan_BAT_ClipBanker_NPB_MTB{
	meta:
		description = "Trojan:BAT/ClipBanker.NPB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {06 02 07 6f 2d 00 00 0a 7e 90 01 02 00 04 07 7e 90 01 02 00 04 8e 69 5d 91 61 28 90 01 02 00 0a 6f 67 00 00 0a 26 07 17 58 0b 90 00 } //01 00 
		$a_01_1 = {4f 2e 4e 2e 72 65 73 6f 75 72 63 65 73 } //00 00 
	condition:
		any of ($a_*)
 
}