
rule Trojan_BAT_PureCrypt_CCDN_MTB{
	meta:
		description = "Trojan:BAT/PureCrypt.CCDN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {09 11 05 16 6f 90 01 04 13 06 12 06 28 90 01 04 13 07 11 04 11 07 6f 90 01 04 11 05 17 58 13 05 11 05 09 6f 90 01 04 32 d3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}