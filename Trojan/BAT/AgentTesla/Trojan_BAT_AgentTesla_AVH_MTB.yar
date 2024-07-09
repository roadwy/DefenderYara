
rule Trojan_BAT_AgentTesla_AVH_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AVH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 "
		
	strings :
		$a_02_0 = {26 16 00 28 ?? ?? ?? 0a 14 72 ?? ?? ?? 70 17 8d ?? ?? ?? 01 25 16 03 a2 25 13 ?? 14 14 17 8d ?? ?? ?? 01 25 16 17 9c 25 13 } //10
		$a_80_1 = {47 65 74 4d 65 74 68 6f 64 } //GetMethod  1
		$a_80_2 = {49 6e 76 6f 6b 65 } //Invoke  1
		$a_80_3 = {53 69 6d 70 6c 65 55 49 } //SimpleUI  1
	condition:
		((#a_02_0  & 1)*10+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=13
 
}