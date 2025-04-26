
rule Trojan_BAT_AgentTesla_ABAC_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {07 02 8e 69 6f ?? ?? ?? 0a 8d ?? ?? ?? 01 0d 07 02 16 02 8e 69 09 16 6f ?? ?? ?? 0a 13 04 07 09 11 04 6f ?? ?? ?? 0a 26 28 ?? ?? ?? 0a 09 6f ?? ?? ?? 0a 72 ?? ?? ?? 70 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 13 05 de 0b } //1
		$a_01_1 = {47 63 6d 42 6c 6f 63 6b 43 69 70 68 65 72 } //1 GcmBlockCipher
		$a_01_2 = {4d 00 41 00 58 00 43 00 41 00 52 00 45 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //1 MAXCARE.Properties.Resources
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}