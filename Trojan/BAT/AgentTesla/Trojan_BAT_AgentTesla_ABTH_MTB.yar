
rule Trojan_BAT_AgentTesla_ABTH_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABTH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {52 65 61 64 41 73 42 79 74 65 41 72 72 61 79 41 73 79 6e } //1 ReadAsByteArrayAsyn
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_2 = {31 00 30 00 39 00 2e 00 32 00 30 00 36 00 2e 00 32 00 34 00 33 00 2e 00 31 00 39 00 33 00 2f 00 62 00 69 00 6e 00 2e 00 62 00 6d 00 70 } //3
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*3) >=5
 
}