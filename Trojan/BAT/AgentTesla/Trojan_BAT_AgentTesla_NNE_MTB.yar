
rule Trojan_BAT_AgentTesla_NNE_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NNE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {2b 39 08 09 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 13 04 11 04 28 ?? ?? ?? 06 20 ?? ?? ?? 00 da 13 05 11 05 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 13 06 07 11 06 28 ?? ?? ?? 0a 0b 00 09 17 d6 0d 09 08 6f ?? ?? ?? 0a fe 04 13 07 11 07 2d b8 } //1
		$a_80_1 = {41 6c 70 68 61 2e 42 65 74 61 } //Alpha.Beta  1
		$a_80_2 = {31 42 75 34 6e 69 35 66 75 5f 54 65 78 74 42 6f 78 } //1Bu4ni5fu_TextBox  1
	condition:
		((#a_03_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=3
 
}