
rule Trojan_BAT_XWorm_AAB_MTB{
	meta:
		description = "Trojan:BAT/XWorm.AAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 06 18 6f ?? 00 00 0a 02 28 ?? 00 00 0a 0d 06 6f ?? 00 00 0a 13 04 11 04 09 16 09 8e 69 6f ?? 00 00 0a 13 05 28 ?? 00 00 0a 11 05 6f ?? 00 00 0a 13 06 dd } //4
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}