
rule Trojan_BAT_AgentTesla_HEBBAR_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.HEBBAR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {0d 16 0c 2b 40 00 09 08 93 28 90 01 03 0a 1f 21 32 11 09 08 93 28 90 01 03 0a 1f 7e fe 02 16 fe 01 2b 01 16 13 04 11 04 2c 16 00 09 08 1f 21 09 08 93 1f 0e 58 1f 5e 5d 58 28 90 01 03 0a 9d 00 00 08 17 58 0c 08 07 6f 90 01 03 0a fe 04 13 05 11 05 2d b1 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}