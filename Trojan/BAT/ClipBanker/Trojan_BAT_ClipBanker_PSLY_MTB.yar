
rule Trojan_BAT_ClipBanker_PSLY_MTB{
	meta:
		description = "Trojan:BAT/ClipBanker.PSLY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {28 34 00 00 0a 7e 01 00 00 04 02 08 6f 35 00 00 0a 28 36 00 00 0a a5 01 00 00 1b 0b 11 07 20 fb 9d aa 47 5a 20 c4 30 82 6d 61 38 98 fe ff ff } //00 00 
	condition:
		any of ($a_*)
 
}