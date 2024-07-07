
rule Trojan_BAT_NekoStealer_AAQO_MTB{
	meta:
		description = "Trojan:BAT/NekoStealer.AAQO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {08 16 07 1f 0f 1f 10 28 90 01 01 00 00 0a 06 07 6f 90 01 01 00 00 0a 06 18 6f 90 01 01 00 00 0a 06 1b 6f 90 01 01 00 00 0a 06 6f 90 01 01 00 00 0a 0d 09 03 16 03 8e 69 6f 90 01 01 00 00 0a 2a 90 00 } //4
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}