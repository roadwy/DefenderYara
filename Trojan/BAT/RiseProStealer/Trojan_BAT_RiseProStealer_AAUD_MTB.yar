
rule Trojan_BAT_RiseProStealer_AAUD_MTB{
	meta:
		description = "Trojan:BAT/RiseProStealer.AAUD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 08 11 03 6f 90 01 01 00 00 0a 38 00 00 00 00 00 00 11 08 6f 90 01 01 00 00 0a 13 06 38 00 00 00 00 00 11 06 11 04 16 11 04 8e 69 28 90 01 01 00 00 06 13 0b 90 00 } //4
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}