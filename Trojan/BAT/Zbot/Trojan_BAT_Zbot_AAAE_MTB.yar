
rule Trojan_BAT_Zbot_AAAE_MTB{
	meta:
		description = "Trojan:BAT/Zbot.AAAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 13 04 73 ?? 00 00 0a 13 05 06 11 05 09 11 04 6f ?? 00 00 0a 17 73 ?? 00 00 0a 13 06 11 06 02 16 02 8e 69 6f ?? 00 00 0a 11 06 6f ?? 00 00 0a 06 6f ?? 00 00 0a 73 ?? 00 00 0a 0a } //4
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}