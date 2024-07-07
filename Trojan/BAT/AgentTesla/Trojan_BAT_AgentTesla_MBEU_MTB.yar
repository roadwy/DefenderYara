
rule Trojan_BAT_AgentTesla_MBEU_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBEU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {06 08 5d 0d 06 1f 16 5d 13 0b 06 17 58 08 5d 13 0c 07 09 91 13 0d 20 00 01 00 00 13 04 11 0d 11 06 11 0b 91 61 07 11 0c 91 59 11 04 58 11 04 5d 13 0e 07 09 11 0e d2 9c 06 17 58 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}