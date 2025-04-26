
rule Trojan_BAT_AgentTesla_ASBY_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ASBY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {11 0a 11 07 6f ?? 00 00 0a 5d 13 0b 11 0a 11 07 6f ?? 00 00 0a 5b 13 0c 11 07 72 ?? 01 00 70 18 18 8d ?? 00 00 01 25 16 11 0b 8c ?? 00 00 01 a2 25 17 11 0c 8c ?? 00 00 01 a2 28 } //2
		$a_03_1 = {01 13 0d 12 0d 28 ?? 00 00 0a 13 0e 11 06 11 0e 6f ?? 00 00 0a 11 0a 17 58 13 0a 11 0a 11 07 6f ?? 00 00 0a 11 07 6f ?? 00 00 0a 5a 32 8f } //2
		$a_01_2 = {54 00 61 00 6e 00 64 00 65 00 6d 00 4c 00 69 00 6e 00 65 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //1 TandemLine.Properties.Resources
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1) >=5
 
}