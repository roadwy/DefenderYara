
rule Trojan_BAT_AgentTesla_GPD_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.GPD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {03 00 90 5a 4d 30 00 31 00 32 } //1
		$a_01_1 = {00 52 65 76 65 72 73 65 00 } //1
		$a_01_2 = {6c 6c 64 2e 65 65 72 6f 63 73 6d 00 6e 69 61 4d 6c 6c 44 72 6f 43 5f } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}