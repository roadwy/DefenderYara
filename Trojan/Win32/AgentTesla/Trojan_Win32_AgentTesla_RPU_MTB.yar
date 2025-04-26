
rule Trojan_Win32_AgentTesla_RPU_MTB{
	meta:
		description = "Trojan:Win32/AgentTesla.RPU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {88 1c 38 eb 66 e9 af 00 00 00 } //1
		$a_03_1 = {eb f6 f6 d3 eb 04 [0-20] eb f0 80 f3 6d eb 0a } //1
		$a_03_2 = {80 f3 eb eb 05 [0-20] 8a 1c 38 eb d6 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}