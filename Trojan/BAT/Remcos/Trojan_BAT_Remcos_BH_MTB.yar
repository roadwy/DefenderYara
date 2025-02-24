
rule Trojan_BAT_Remcos_BH_MTB{
	meta:
		description = "Trojan:BAT/Remcos.BH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 0b 07 06 16 73 ?? 00 00 0a 0c 73 ?? 00 00 0a 0d 20 00 04 00 00 8d ?? 00 00 01 13 04 2b 0b 09 11 04 16 11 05 6f ?? 00 00 0a 08 11 04 16 11 04 8e 69 6f ?? 00 00 0a 25 13 05 16 30 } //4
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}