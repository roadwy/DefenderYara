
rule Trojan_BAT_AgentTesla_MBFP_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBFP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_01_0 = {6c 00 6d 00 2e 00 6f 00 51 00 } //10 lm.oQ
		$a_01_1 = {4c 00 6f 00 61 00 64 00 } //1 Load
		$a_81_2 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_81_2  & 1)*1) >=12
 
}