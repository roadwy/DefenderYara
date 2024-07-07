
rule Trojan_BAT_AgentTesla_MBFY_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBFY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {54 56 71 51 e7 be 8e e5 a4 8d e5 a4 8d e5 a4 8d e7 be 8e e5 a4 8d e5 a4 8d e5 a4 8d 4d e7 be 8e e5 a4 8d e5 a4 8d e5 a4 8d e7 be 8e e5 a4 8d e5 a4 8d } //1
		$a_01_1 = {8d e5 a4 8d 34 66 75 67 34 e7 be 8e e5 a4 8d e5 a4 8d e5 a4 8d 74 e7 be 8e e5 a4 8d e5 a4 8d e5 a4 8d 6e 4e 49 62 67 42 54 4d 30 68 56 } //1
		$a_01_2 = {63 6c 65 61 6e 5f 32 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 } //1 clean_2.Resources.resource
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}