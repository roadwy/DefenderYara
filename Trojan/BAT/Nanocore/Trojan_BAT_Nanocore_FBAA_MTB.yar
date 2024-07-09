
rule Trojan_BAT_Nanocore_FBAA_MTB{
	meta:
		description = "Trojan:BAT/Nanocore.FBAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 04 0e 05 0e 04 8e 69 6f ?? 00 00 0a 0a 06 0b 2b 00 07 2a } //4
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}