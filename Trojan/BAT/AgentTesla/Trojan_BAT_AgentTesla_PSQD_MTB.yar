
rule Trojan_BAT_AgentTesla_PSQD_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSQD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {6f 61 00 00 0a 0a 06 72 aa 05 00 70 28 90 01 03 06 28 90 01 03 0a 0b 07 6f 90 01 03 0a 0c 08 2c 24 00 07 6f 90 01 03 0a 17 6f 65 00 00 0a 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}