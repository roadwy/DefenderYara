
rule Trojan_BAT_AgentTesla_OI_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.OI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {06 09 91 7e 90 02 04 7e 90 02 04 6f 90 02 04 74 90 02 04 07 09 28 90 02 04 9c 09 17 d6 0d 09 08 31 90 02 01 7e 90 02 04 7e 90 02 04 06 6f 90 02 05 73 90 02 04 20 90 02 04 20 90 02 04 6f 90 02 04 28 90 02 04 6f 90 02 05 28 90 02 05 2a 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}