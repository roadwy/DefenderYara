
rule Trojan_BAT_AgentTesla_JHC_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.JHC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_03_0 = {04 94 02 7b ?? ?? ?? 04 02 7b ?? ?? ?? 04 94 58 20 ?? ?? ?? 00 5d 94 7d ?? ?? ?? 04 02 7b ?? ?? ?? 04 02 7b ?? ?? ?? 04 06 02 7b ?? ?? ?? 04 91 02 7b ?? ?? ?? 04 61 d2 9c 02 02 7b ?? ?? ?? 04 17 58 7d } //10
		$a_81_1 = {47 65 74 4d 65 74 68 6f 64 } //1 GetMethod
		$a_81_2 = {52 65 70 6c 61 63 65 } //1 Replace
	condition:
		((#a_03_0  & 1)*10+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=12
 
}