
rule Trojan_BAT_AgentTesla_ERQ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ERQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {02 05 04 5d 91 03 05 1f 16 5d 90 01 05 61 90 01 05 0a 90 00 } //1
		$a_03_1 = {20 00 01 00 00 0a 03 04 20 00 14 01 00 5d 03 02 20 00 14 01 00 04 90 01 05 03 04 17 58 20 00 14 01 00 5d 91 90 01 05 59 06 58 06 5d 90 01 05 9c 03 0b 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}