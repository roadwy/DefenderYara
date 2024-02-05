
rule Trojan_BAT_AgentTesla_NUC_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NUC!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {c7 06 c7 06 c7 06 c7 06 c7 06 c7 06 c7 06 c7 06 c7 06 c7 06 c7 06 ed 06 c7 06 c7 06 c7 06 c7 06 c7 06 ba 06 ec 06 fb 06 ed 06 ba 06 c7 06 fa 06 c7 06 f4 06 } //01 00 
		$a_01_1 = {c7 06 d7 06 b1 06 fd 06 c7 06 c7 06 dd 06 d8 06 d3 06 d4 06 d1 06 be 06 d3 06 d8 06 ca 06 ef 06 c8 06 f0 06 c7 06 d7 06 c7 06 c7 06 f1 06 ff 06 c9 06 b6 06 fb 06 fd 06 c7 06 c7 06 dd 06 d9 06 fc 06 f9 06 } //01 00 
		$a_01_2 = {00 07 c7 06 c9 06 ba 06 c7 06 d3 06 c7 06 c7 06 fb 06 c7 06 ca 06 c7 06 c7 06 c7 06 c7 06 c7 06 c7 06 c7 06 c7 06 c7 06 c7 06 c7 06 c7 06 c7 06 c7 06 c7 06 c7 06 c7 06 } //00 00 
	condition:
		any of ($a_*)
 
}