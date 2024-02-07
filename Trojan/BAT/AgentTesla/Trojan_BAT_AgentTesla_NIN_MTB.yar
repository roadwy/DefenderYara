
rule Trojan_BAT_AgentTesla_NIN_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NIN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 01 00 "
		
	strings :
		$a_01_0 = {cb 00 cd 00 e8 00 c8 00 b8 00 b8 00 c4 00 b8 00 b8 00 b8 00 b8 00 bc 00 } //01 00 
		$a_01_1 = {e5 00 da 00 e4 00 bd 00 eb 00 c0 00 be 00 c5 00 df 00 d9 00 e4 00 ac 00 } //01 00 
		$a_01_2 = {c2 00 b8 00 bc 00 b8 00 b8 00 ba 00 ea 00 e4 00 be 00 df 00 c4 00 c3 00 c2 00 ae 00 cc 00 c9 00 b9 00 } //01 00 
		$a_01_3 = {cd 00 e2 00 f0 00 ba 00 db 00 bd 00 c8 00 b8 00 b8 00 ce 00 c9 00 c4 00 c5 00 } //01 00 
		$a_01_4 = {a6 00 a6 00 af 00 c9 00 b9 00 b8 00 c2 00 c6 00 d8 00 c9 00 db 00 d1 00 a6 00 de 00 c0 00 } //01 00 
		$a_81_5 = {46 72 6f 6d 42 61 73 65 36 34 43 68 61 72 41 72 72 61 79 } //01 00  FromBase64CharArray
		$a_81_6 = {49 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 35 } //01 00  I__________________5
		$a_81_7 = {47 65 74 45 78 70 6f 72 74 65 64 54 79 70 65 73 } //01 00  GetExportedTypes
		$a_81_8 = {54 6f 43 68 61 72 41 72 72 61 79 } //01 00  ToCharArray
		$a_81_9 = {54 6f 53 74 72 69 6e 67 } //00 00  ToString
	condition:
		any of ($a_*)
 
}