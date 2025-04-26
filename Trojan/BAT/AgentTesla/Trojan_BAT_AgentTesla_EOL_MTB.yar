
rule Trojan_BAT_AgentTesla_EOL_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EOL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {dd 00 a6 00 a6 00 a6 00 ee 00 c0 00 ba 00 e1 00 e4 00 e2 00 cf 00 ce 00 d1 00 bc 00 dd 00 da 00 be 00 bc 00 c3 00 bf 00 ee 00 ea 00 cb 00 ba 00 } //1
		$a_01_1 = {c9 00 c4 00 c1 00 c6 00 c4 00 a6 00 a2 00 a6 00 a6 00 af 00 c9 00 b9 00 b9 00 db 00 d0 00 bc 00 ee 00 c8 00 c9 00 ba 00 ef 00 b0 00 af 00 e2 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}