
rule Trojan_BAT_AgentTesla_HD_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.HD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 "
		
	strings :
		$a_02_0 = {0a 08 16 17 73 ?? ?? ?? 0a 0b 73 ?? ?? ?? 0a 0d 1f 40 8d ?? ?? ?? 01 0a 15 13 04 07 06 16 06 8e b7 6f ?? ?? ?? 0a 13 04 38 ?? ?? ?? 00 09 06 16 11 04 6f ?? ?? ?? 0a 07 06 16 06 8e b7 6f ?? ?? ?? 0a 13 04 11 04 } //10
		$a_80_1 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //CreateInstance  1
		$a_80_2 = {47 65 74 4d 65 74 68 6f 64 } //GetMethod  1
		$a_80_3 = {54 6f 41 72 72 61 79 } //ToArray  1
	condition:
		((#a_02_0  & 1)*10+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=13
 
}