
rule Trojan_BAT_QuasarRat_AMAC_MTB{
	meta:
		description = "Trojan:BAT/QuasarRat.AMAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 00 11 05 11 04 1f 10 6f ?? ?? 00 0a 6f ?? ?? 00 0a 00 11 05 11 05 6f ?? ?? 00 0a 11 05 6f ?? ?? 00 0a 6f ?? ?? 00 0a 13 06 11 06 02 74 ?? 00 00 1b 16 02 14 72 ?? ?? ?? 70 16 } //4
		$a_80_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //CreateDecryptor  1
	condition:
		((#a_03_0  & 1)*4+(#a_80_1  & 1)*1) >=5
 
}