
rule Trojan_BAT_AgentTesla_NAG_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NAG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {28 0f 00 00 0a 72 ?? 00 00 70 28 ?? 00 00 06 6f ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 2b 28 ?? 00 00 2b 13 01 } //5
		$a_01_1 = {68 6a 6b 6a 2e 65 78 65 } //1 hjkj.exe
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}
rule Trojan_BAT_AgentTesla_NAG_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.NAG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {02 72 23 00 00 70 6f ?? ?? ?? 0a 00 02 02 fe ?? ?? ?? ?? 06 73 ?? ?? ?? 0a 28 ?? ?? ?? 0a 00 02 16 28 ?? ?? ?? 0a 00 2a } //5
		$a_01_1 = {47 50 54 34 5f 56 32 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //1 GPT4_V2.Properties.Resources
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}
rule Trojan_BAT_AgentTesla_NAG_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.NAG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {13 04 2b 52 00 08 09 11 04 28 ?? ?? ?? 06 13 07 d0 ?? ?? ?? 01 28 ?? ?? ?? 0a 72 ?? ?? ?? 70 20 ?? ?? ?? 00 14 14 17 8d ?? ?? ?? 01 25 16 11 07 8c ?? ?? ?? 01 a2 28 ?? ?? ?? 0a a5 ?? ?? ?? 01 13 08 17 13 09 07 11 08 d2 6f ?? ?? ?? 0a 00 00 11 04 17 58 13 04 11 04 17 fe 04 13 0a 11 0a 2d a3 06 17 58 0a 00 09 } //1
		$a_01_1 = {49 5f 5f 5f 5f 5f 5f 5f 49 } //1 I_______I
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}