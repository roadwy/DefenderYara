
rule Trojan_BAT_AgentTesla_VAMO_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.VAMO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {d0 1f 00 00 01 28 90 01 03 0a 72 25 02 00 70 17 8d 47 00 00 01 25 16 1f 60 9d 28 90 01 03 0a 20 00 01 00 00 14 14 17 8d 1b 00 00 01 25 16 02 a2 28 90 01 03 0a 74 1f 00 00 01 0a 2b 00 06 2a 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}