
rule Trojan_BAT_AgentTesla_PSST_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSST!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {28 18 00 00 0a 6f 19 00 00 0a 6f 1a 00 00 0a 6f 1b 00 00 0a 6f 1c 00 00 0a 0a 28 1d 00 00 0a 06 6f 1e 00 00 0a 28 1f 00 00 0a 0a 73 20 00 00 0a 0b 07 6f 21 00 00 0a 16 fe 01 0c 08 2c 07 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}