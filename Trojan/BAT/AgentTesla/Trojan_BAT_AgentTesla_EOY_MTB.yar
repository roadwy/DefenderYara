
rule Trojan_BAT_AgentTesla_EOY_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EOY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {d0 00 cb 00 d0 00 e4 00 c1 00 a9 00 c5 00 df 00 bd 00 cb 00 c4 00 a9 00 e2 00 bb 00 c4 00 eb 00 e2 00 f1 00 c5 00 a8 00 e2 00 cb 00 c3 00 ee 00 d0 00 f1 } //1
		$a_01_1 = {ee 00 da 00 e3 00 e3 00 a9 00 d1 00 ed 00 ef 00 a9 00 d9 00 ec 00 df 00 a9 00 d0 00 e3 00 c9 00 bd 00 c0 00 a8 00 d1 00 ce 00 d8 00 ec 00 cd 00 e5 00 c8 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}