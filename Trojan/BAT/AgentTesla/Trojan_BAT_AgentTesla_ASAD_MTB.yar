
rule Trojan_BAT_AgentTesla_ASAD_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ASAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 0b 07 6f ?? 00 00 0a 16 fe 01 0c 08 2c 0a 00 07 06 6f ?? 00 00 0a 00 00 07 6f ?? 00 00 0a 00 07 6f ?? 00 00 0a 0d 2b 00 09 2a } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}