
rule Trojan_BAT_AgentTesla_SIL_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.SIL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 01 00 "
		
	strings :
		$a_01_0 = {cb 00 cd 00 e8 00 c8 00 b8 00 b8 00 c4 00 b8 00 b8 00 b8 00 b8 00 bc 00 b8 00 b8 00 b8 00 b8 00 } //01 00 
		$a_01_1 = {e5 00 da 00 e4 00 bd 00 eb 00 c0 00 be 00 c5 00 df 00 d9 00 e4 00 ac 00 } //01 00 
		$a_01_2 = {bc 00 c1 00 c9 00 c8 00 d0 00 b8 00 b8 00 b8 00 b8 00 e8 00 b8 00 } //01 00 
		$a_01_3 = {d0 00 c4 00 bf 00 ee 00 e6 00 cb 00 ba 00 f1 00 de 00 e0 00 a6 00 ed 00 } //01 00 
		$a_81_4 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_81_5 = {49 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 32 } //01 00  I______________________2
		$a_01_6 = {44 00 65 00 74 00 65 00 63 00 74 00 43 00 50 00 55 00 } //01 00  DetectCPU
		$a_81_7 = {54 6f 43 68 61 72 41 72 72 61 79 } //01 00  ToCharArray
		$a_81_8 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //00 00  InvokeMember
	condition:
		any of ($a_*)
 
}