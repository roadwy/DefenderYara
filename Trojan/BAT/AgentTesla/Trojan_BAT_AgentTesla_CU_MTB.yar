
rule Trojan_BAT_AgentTesla_CU_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.CU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_02_0 = {00 06 20 00 01 00 00 6f 90 01 04 00 06 20 90 01 04 6f 90 01 04 00 7e 07 00 00 04 7e 06 00 00 04 20 90 01 04 73 90 01 04 0b 06 07 06 6f 90 01 04 1e 5b 6f 90 01 04 6f 90 01 04 00 06 07 06 6f 90 01 04 1e 5b 6f 90 01 04 6f 90 01 04 00 06 17 6f 90 01 04 00 02 06 6f 90 00 } //10
		$a_81_1 = {43 6c 61 73 73 4c 69 62 72 61 72 79 } //1 ClassLibrary
	condition:
		((#a_02_0  & 1)*10+(#a_81_1  & 1)*1) >=11
 
}