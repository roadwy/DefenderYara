
rule Trojan_BAT_AgentTesla_EOC_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EOC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {ba 00 ea 00 cf 00 ce 00 dd 00 ab 00 b9 00 bc 00 ee 00 cc 00 dd 00 bb 00 df 00 c4 00 c1 00 c6 00 b8 00 c3 00 a6 00 a6 00 a6 00 af 00 c9 00 b9 00 ca 00 ee 00 c1 00 bf 00 ef 00 } //01 00 
		$a_01_1 = {a6 00 bc 00 c8 00 ea 00 de 00 d8 00 ee 00 bc 00 b8 00 b8 00 c1 00 c4 00 de 00 ad 00 e0 00 e6 00 b8 00 b8 00 bd 00 e2 00 e9 00 ad 00 c9 00 d0 00 } //01 00 
		$a_01_2 = {00 46 72 6f 6d 42 61 73 65 36 34 } //00 00 
	condition:
		any of ($a_*)
 
}