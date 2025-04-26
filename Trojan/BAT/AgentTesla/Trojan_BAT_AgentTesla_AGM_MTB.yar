
rule Trojan_BAT_AgentTesla_AGM_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AGM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 04 00 00 "
		
	strings :
		$a_03_0 = {20 00 40 00 00 13 04 07 14 72 ?? ?? ?? 70 17 8d ?? ?? ?? 01 25 16 16 8c ?? ?? ?? 01 a2 14 14 28 ?? ?? ?? 0a 00 11 04 17 da 17 d6 8d ?? ?? ?? 01 13 05 08 28 ?? ?? ?? ?? ?? ?? ?? ?? ?? 18 19 8d ?? ?? ?? 01 25 16 11 05 a2 25 17 16 } //10
		$a_80_1 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //CreateInstance  2
		$a_80_2 = {47 65 74 54 79 70 65 } //GetType  2
		$a_80_3 = {52 65 76 65 72 73 65 } //Reverse  2
	condition:
		((#a_03_0  & 1)*10+(#a_80_1  & 1)*2+(#a_80_2  & 1)*2+(#a_80_3  & 1)*2) >=16
 
}