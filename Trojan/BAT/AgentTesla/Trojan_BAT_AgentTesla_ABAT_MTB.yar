
rule Trojan_BAT_AgentTesla_ABAT_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABAT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 11 07 11 08 6f ?? 00 00 0a 13 0b 12 0b 28 ?? 00 00 0a 13 0c 12 0b 28 ?? 00 00 0a 13 0d 12 0b 28 ?? 00 00 0a 13 0e 11 05 2c 0a 11 09 1f 32 5d 16 fe 01 2b 01 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}