
rule Trojan_BAT_AgentTesla_ABFX_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABFX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {08 07 11 08 9a 1f 10 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 00 11 08 17 58 13 08 11 08 20 ?? ?? ?? 00 fe 04 13 09 11 09 2d d9 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}