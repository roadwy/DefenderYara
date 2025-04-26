
rule Trojan_BAT_AgentTesla_SWB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.SWB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {7e 94 03 00 04 28 73 06 00 0a 7e 95 03 00 04 2c 03 17 2b 03 16 2b 00 2d 1c 28 01 00 00 0a 14 fe 06 5e 06 00 06 73 74 06 00 0a 6f 75 06 00 0a 17 80 95 03 00 04 de 0b 7e 94 03 00 04 28 76 06 00 0a dc } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}