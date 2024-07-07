
rule Trojan_BAT_AgentTesla_NYA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NYA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {57 3f b6 1f 09 1f 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 05 01 00 00 3d 00 00 00 c4 01 00 00 a9 07 00 00 c2 } //1
		$a_01_1 = {02 00 00 04 00 00 00 2e 02 00 00 b4 00 00 00 b0 05 00 00 06 00 00 00 85 00 00 00 03 00 00 00 0c 00 00 00 1f 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}