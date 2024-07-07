
rule Trojan_BAT_AgentTesla_OO_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.OO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {11 09 1f 54 61 13 90 01 01 11 90 01 01 1f 90 01 01 58 45 90 02 18 1f 90 01 01 28 90 01 04 13 90 01 01 2b 90 01 01 16 0a 1f 90 01 01 28 90 01 04 13 90 01 01 2b 90 01 01 20 90 01 04 8d 90 01 04 0c 15 13 90 01 01 2b 90 01 01 d0 90 01 04 26 1f 90 01 01 13 90 01 01 2b 90 01 01 28 90 01 04 0b 1f 90 01 01 13 90 01 01 2b 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}