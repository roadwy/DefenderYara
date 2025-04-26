
rule Trojan_BAT_AgentTesla_NYF_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NYF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {57 b5 a2 3f 09 0f 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 4b 00 00 00 28 00 00 00 57 00 00 00 8a 00 00 00 cd 00 00 00 } //1
		$a_01_1 = {6a 00 00 00 18 00 00 00 03 00 00 00 04 00 00 00 1a 00 00 00 02 00 00 00 03 00 00 00 04 00 00 00 01 00 00 00 01 00 00 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}