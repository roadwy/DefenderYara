
rule Trojan_BAT_AgentTesla_PHHZ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PHHZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {17 fe 02 13 06 11 06 2c 0e 03 12 02 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 00 09 18 fe 02 13 07 11 07 2c 0e 03 12 02 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 00 00 03 6f ?? ?? ?? 0a 04 fe 04 16 fe 01 13 08 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}