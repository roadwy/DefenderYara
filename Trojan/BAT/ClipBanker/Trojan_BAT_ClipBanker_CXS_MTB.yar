
rule Trojan_BAT_ClipBanker_CXS_MTB{
	meta:
		description = "Trojan:BAT/ClipBanker.CXS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {06 02 07 6f 90 01 04 25 26 7e 90 01 04 07 7e 90 01 04 8e 69 5d 91 61 28 90 01 04 6f 90 01 04 25 26 26 07 17 58 0b 07 02 6f 90 01 04 25 26 32 90 00 } //01 00 
		$a_01_1 = {43 6f 6e 74 61 69 6e 73 4b 65 79 } //00 00 
	condition:
		any of ($a_*)
 
}