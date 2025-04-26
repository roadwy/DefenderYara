
rule Trojan_BAT_AgentTesla_AACC_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AACC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {08 11 09 11 08 6f ?? 00 00 0a 13 0a 16 13 0b 11 05 11 07 9a 72 8d 02 00 70 28 ?? 00 00 0a 13 0c 11 0c 2c 0d 00 12 0a 28 ?? 00 00 0a 13 0b 00 2b 42 11 05 11 07 9a 72 91 02 00 70 28 ?? 00 00 0a 13 0d 11 0d 2c 0d 00 12 0a 28 ?? 00 00 0a 13 0b 00 2b 20 11 05 11 07 9a 72 95 02 00 70 28 ?? 00 00 0a 13 0e 11 0e 2c 0b 00 12 0a 28 ?? 00 00 0a 13 0b 00 07 11 0b 6f ?? 00 00 0a 00 00 11 09 17 58 13 09 11 09 09 fe 04 13 0f 11 0f 3a } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}