
rule Trojan_BAT_AgentTesla_ASFU_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ASFU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {06 09 5d 13 05 06 11 08 5d 13 0a 06 17 58 09 5d 13 0b 07 11 05 91 11 04 11 0a 91 61 20 00 01 00 00 13 06 07 11 0b 91 59 11 06 58 11 06 5d 13 0c 07 11 05 11 0c d2 9c 06 17 58 0a 06 09 11 07 17 58 5a 32 bc } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}