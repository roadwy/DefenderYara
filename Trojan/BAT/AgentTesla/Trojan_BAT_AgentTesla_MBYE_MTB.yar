
rule Trojan_BAT_AgentTesla_MBYE_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBYE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {17 58 08 5d 0d 06 07 91 1f 90 01 01 8d 90 01 01 00 00 01 25 90 00 } //1
		$a_03_1 = {5f 9c 58 09 5d 13 06 07 08 91 1f 90 01 01 8d 90 01 01 00 00 01 25 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}