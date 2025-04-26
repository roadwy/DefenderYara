
rule Trojan_BAT_AgentTesla_PSGW_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSGW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {28 22 00 00 06 0b 07 1f 20 8d 1f 00 00 01 25 d0 34 00 00 04 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 07 1f 10 8d 1f 00 00 01 25 d0 37 00 00 04 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 06 07 6f ?? ?? ?? 0a 17 73 ?? ?? ?? 0a 25 02 16 02 8e 69 6f ?? ?? ?? 0a 6f 99 00 00 0a } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}