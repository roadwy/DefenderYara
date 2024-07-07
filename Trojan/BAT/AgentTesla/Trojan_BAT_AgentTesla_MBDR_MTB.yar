
rule Trojan_BAT_AgentTesla_MBDR_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBDR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {ff 11 08 72 90 01 01 0d 00 70 72 90 01 01 01 00 70 6f 90 01 01 00 00 0a 72 90 01 01 0d 00 70 72 90 01 01 0d 00 70 6f 90 01 01 00 00 0a 13 08 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}