
rule Trojan_BAT_AgentTesla_MVD_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MVD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 05 11 06 59 7e 03 00 00 04 28 01 00 00 2b 58 7e 03 00 00 04 28 01 00 00 2b 5d d1 13 07 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}