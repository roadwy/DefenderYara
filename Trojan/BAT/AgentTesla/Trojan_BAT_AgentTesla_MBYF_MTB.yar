
rule Trojan_BAT_AgentTesla_MBYF_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBYF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {3c 4d 6f 64 75 6c 65 3e 00 45 75 67 65 6e 65 00 4f 62 6a 65 63 74 00 50 72 6f 67 72 61 6d 00 41 6e 67 65 6c 6f 00 52 65 6d 6f 74 65 4f 62 6a 65 63 74 73 } //1
		$a_01_1 = {4e 00 45 00 54 00 43 00 72 00 79 00 70 00 74 00 2e 00 65 00 78 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}