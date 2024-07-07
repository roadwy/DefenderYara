
rule Trojan_BAT_AgentTesla_MPJ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MPJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {0a 06 16 72 90 01 04 a2 06 17 72 90 01 04 a2 06 90 01 14 17 8d 90 01 04 0b 07 16 02 7b 90 01 04 a2 07 28 0e 00 00 06 90 02 0a 2a 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}