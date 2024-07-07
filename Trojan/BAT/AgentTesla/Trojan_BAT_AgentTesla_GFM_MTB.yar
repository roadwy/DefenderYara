
rule Trojan_BAT_AgentTesla_GFM_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.GFM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {25 16 1f 25 9d 6f 90 01 03 0a 0b 07 8e 69 8d 2c 00 00 01 0c 16 0d 2b 11 08 09 07 09 9a 1f 10 28 90 01 03 0a 9c 09 17 58 0d 09 07 8e 69 32 e9 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}