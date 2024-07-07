
rule Trojan_BAT_AgentTesla_CCGT_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.CCGT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 10 1f 16 5d 91 13 16 11 0b 11 14 91 11 11 58 13 17 11 15 11 16 61 13 18 11 18 11 17 59 13 19 11 0b 11 13 11 19 11 11 5d d2 9c 00 11 10 17 58 13 10 11 10 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}