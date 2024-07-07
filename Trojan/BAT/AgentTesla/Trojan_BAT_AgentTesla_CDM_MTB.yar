
rule Trojan_BAT_AgentTesla_CDM_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.CDM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {06 11 04 28 90 01 03 0a 08 11 04 08 6f 90 01 03 0a 5d 17 d6 28 90 01 03 0a da 13 05 07 11 05 28 90 01 03 0a 28 90 01 03 0a 28 90 01 03 0a 0b 11 04 17 d6 13 04 11 04 09 31 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}