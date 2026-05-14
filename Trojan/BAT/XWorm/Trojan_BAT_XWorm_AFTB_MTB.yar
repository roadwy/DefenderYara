
rule Trojan_BAT_XWorm_AFTB_MTB{
	meta:
		description = "Trojan:BAT/XWorm.AFTB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 13 04 08 11 04 6f ?? ?? 00 0a 00 11 04 6f ?? ?? 00 0a 13 05 00 28 ?? ?? 00 0a 13 06 11 06 07 6f ?? ?? 00 0a 00 11 06 07 6f ?? ?? 00 0a 00 11 06 17 6f ?? ?? 00 0a 00 11 06 18 6f ?? ?? 00 0a 00 00 11 06 6f ?? ?? 00 0a 13 07 11 05 11 07 28 ?? ?? 00 06 28 ?? ?? 00 2b 0a de 36 } //5
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}