
rule Trojan_BAT_RiseProStealer_AANC_MTB{
	meta:
		description = "Trojan:BAT/RiseProStealer.AANC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 04 00 "
		
	strings :
		$a_03_0 = {11 05 07 28 90 01 01 00 00 06 00 11 05 17 28 90 01 01 00 00 06 00 11 05 09 28 90 01 01 00 00 06 00 00 11 05 28 90 01 01 00 00 06 13 06 11 06 11 04 16 11 04 8e 69 28 90 01 01 00 00 06 13 07 90 00 } //01 00 
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //00 00  CreateDecryptor
	condition:
		any of ($a_*)
 
}