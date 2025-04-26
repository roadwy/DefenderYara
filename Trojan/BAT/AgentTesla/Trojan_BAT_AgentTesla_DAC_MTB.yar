
rule Trojan_BAT_AgentTesla_DAC_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.DAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {07 02 08 93 06 08 06 6f ?? ?? ?? 0a 5d 6f ?? ?? ?? 0a 61 d1 6f ?? ?? ?? 0a 26 08 17 58 0c 08 02 8e 69 } //1
		$a_01_1 = {54 6f 43 68 61 72 41 72 72 61 79 } //1 ToCharArray
		$a_01_2 = {46 72 6f 6d 42 61 73 65 36 34 } //1 FromBase64
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}