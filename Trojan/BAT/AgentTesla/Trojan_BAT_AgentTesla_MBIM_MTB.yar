
rule Trojan_BAT_AgentTesla_MBIM_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBIM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {11 06 11 0f 17 8d ?? ?? ?? 01 25 16 11 05 11 0f 9a 1f 10 28 ?? 00 00 0a 9c 6f ?? 00 00 0a 00 11 0f 17 d6 13 0f 11 0f 11 0e 31 d5 } //1
		$a_03_1 = {72 29 09 00 70 72 2f 09 00 70 6f ?? 00 00 0a 0c 08 72 35 09 00 70 72 35 02 00 70 } //1
		$a_01_2 = {4c 00 6f 00 2d 00 61 00 64 00 20 00 01 03 2d 00 01 11 44 00 65 00 6c 00 65 00 74 00 65 00 4d 00 43 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}