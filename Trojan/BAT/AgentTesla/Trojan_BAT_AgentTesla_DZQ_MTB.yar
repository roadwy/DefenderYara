
rule Trojan_BAT_AgentTesla_DZQ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.DZQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {08 11 04 02 11 04 91 07 61 06 09 91 61 28 90 01 03 0a 9c 09 03 6f 90 01 03 0a 17 59 90 00 } //1
		$a_03_1 = {06 02 08 18 6f 90 01 03 0a 1f 10 28 90 01 03 0a 84 28 90 01 03 0a 6f 90 01 03 0a 26 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}