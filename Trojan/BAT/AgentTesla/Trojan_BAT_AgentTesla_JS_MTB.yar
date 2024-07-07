
rule Trojan_BAT_AgentTesla_JS_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.JS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {11 04 18 6f 90 01 01 00 00 0a 20 03 02 00 00 28 90 01 01 00 00 0a 13 07 90 00 } //2
		$a_03_1 = {13 05 11 05 6f 90 01 01 00 00 0a 16 9a 72 90 00 } //2
		$a_01_2 = {54 6f 41 72 72 61 79 } //1 ToArray
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1) >=5
 
}