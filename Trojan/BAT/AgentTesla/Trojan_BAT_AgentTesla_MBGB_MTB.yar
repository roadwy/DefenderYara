
rule Trojan_BAT_AgentTesla_MBGB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBGB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {20 01 68 00 00 8d 90 01 01 00 00 01 0d 16 0a 2b 1d 08 06 18 6f 90 01 01 00 00 0a 13 08 09 06 18 5b 11 08 1f 10 28 90 01 01 00 00 0a d2 9c 06 18 58 0a 06 20 02 d0 00 00 fe 04 13 09 11 09 2d d5 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}