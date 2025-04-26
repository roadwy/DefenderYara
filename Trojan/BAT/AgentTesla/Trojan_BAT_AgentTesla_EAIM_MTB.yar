
rule Trojan_BAT_AgentTesla_EAIM_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EAIM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {08 11 05 58 1f 64 5d 13 06 08 11 05 5a 1f 64 5d 13 07 08 11 05 61 1f 64 5d 13 08 02 08 11 05 6f 57 00 00 0a 13 09 04 03 6f 58 00 00 0a 59 13 0a 11 09 11 0a 03 28 11 00 00 06 11 05 17 58 13 05 11 05 02 6f 59 00 00 0a 2f 09 03 6f 58 00 00 0a 04 32 ad } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}