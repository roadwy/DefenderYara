
rule Trojan_BAT_Seraph_AAIY_MTB{
	meta:
		description = "Trojan:BAT/Seraph.AAIY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {06 20 39 97 2e d7 28 ?? 02 00 06 28 ?? 01 00 0a 6f ?? ?? 00 0a 06 20 74 97 2e d7 28 ?? 02 00 06 28 ?? 01 00 0a 6f ?? ?? 00 0a 06 06 6f ?? 00 00 0a 06 6f ?? 01 00 0a 6f ?? 00 00 0a 13 04 73 ?? 00 00 0a 0c 08 11 04 17 73 ?? 00 00 0a 0d 09 07 16 07 8e 69 6f ?? 00 00 0a 08 6f ?? 00 00 0a 13 05 de 1e 09 6f ?? 00 00 0a dc } //5
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}