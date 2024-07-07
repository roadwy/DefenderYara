
rule Trojan_BAT_AgentTesla_JW_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.JW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {04 05 28 82 00 00 0a 04 28 90 01 01 00 00 0a 05 28 90 01 01 00 00 0a 28 90 01 01 00 00 0a 28 90 01 01 00 00 0a 28 85 00 00 0a 0a 90 00 } //2
		$a_01_1 = {02 03 5d 0c 08 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}