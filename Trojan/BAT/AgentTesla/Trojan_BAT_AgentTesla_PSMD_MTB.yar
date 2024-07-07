
rule Trojan_BAT_AgentTesla_PSMD_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSMD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 73 72 00 00 0a 0d 04 28 6d 00 00 0a 13 04 16 13 05 00 11 04 11 05 9a 13 06 11 06 7e 34 02 00 04 6f 6e 00 00 0a 13 07 11 07 2c 30 00 17 0b 09 7e b2 02 00 04 03 28 15 00 00 0a 6f 73 00 00 0a 00 02 11 06 7e 34 02 00 04 14 6f 6f 00 00 0a 6f 70 00 00 0a 7d 0c 00 00 04 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}