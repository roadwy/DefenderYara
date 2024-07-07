
rule Trojan_BAT_AgentTesla_PSJE_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSJE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 00 72 08 23 00 70 72 ec 22 00 70 28 90 01 03 06 72 0c 23 00 70 72 10 23 00 70 6f 90 01 03 0a 72 16 23 00 70 72 1a 23 00 70 6f 90 01 03 0a 13 00 38 76 fd ff ff 00 02 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}