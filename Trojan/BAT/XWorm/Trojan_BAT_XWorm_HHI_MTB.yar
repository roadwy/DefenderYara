
rule Trojan_BAT_XWorm_HHI_MTB{
	meta:
		description = "Trojan:BAT/XWorm.HHI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 07 1f 10 8d ?? 00 00 01 25 d0 ?? 01 00 04 28 ?? 00 00 0a 6f ?? 00 00 0a 06 07 6f ?? 00 00 0a 17 73 ?? 00 00 0a 25 02 16 02 8e 69 6f ?? 00 00 0a 6f ?? 00 00 0a 06 28 ?? 00 00 06 00 2a } //10
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}