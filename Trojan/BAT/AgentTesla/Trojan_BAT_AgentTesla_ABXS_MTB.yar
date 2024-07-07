
rule Trojan_BAT_AgentTesla_ABXS_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABXS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 0d 2b 2d 07 09 18 6f 90 01 01 00 00 0a 1f 10 28 90 01 01 00 00 0a 28 90 01 01 00 00 0a 16 91 13 05 08 17 8d 90 01 01 00 00 01 25 16 11 05 9c 6f 90 01 01 00 00 0a 09 18 58 0d 09 07 6f 90 01 01 00 00 0a fe 04 13 06 11 06 2d c4 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}