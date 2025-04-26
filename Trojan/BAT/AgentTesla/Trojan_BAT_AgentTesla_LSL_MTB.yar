
rule Trojan_BAT_AgentTesla_LSL_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.LSL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {0a 13 04 11 04 28 ?? ?? ?? 06 28 ?? ?? ?? 0a 13 05 07 11 05 28 ?? ?? ?? 0a 0b 00 09 17 d6 0d 09 08 6f ?? ?? ?? 0a fe 04 13 06 11 06 2d cc } //1
		$a_01_1 = {0a 0b 07 0a 2b 00 06 2a } //1 ଊਇ+⨆
		$a_01_2 = {64 00 5f 00 ac 00 5f 00 5f 00 71 00 5f 00 4c 00 62 00 5f 00 b3 00 5f } //1
		$a_01_3 = {54 30 30 30 33 } //1 T0003
		$a_01_4 = {63 6f 72 65 39 38 31 33 32 34 } //1 core981324
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}