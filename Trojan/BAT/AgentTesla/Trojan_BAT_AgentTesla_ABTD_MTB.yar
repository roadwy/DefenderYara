
rule Trojan_BAT_AgentTesla_ABTD_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABTD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 11 07 18 6f ?? ?? ?? 0a 20 03 02 00 00 28 ?? ?? ?? 0a 13 08 09 11 08 6f ?? ?? ?? 0a 00 00 11 07 18 58 13 07 11 07 07 6f ?? ?? ?? 0a fe 04 13 09 11 09 2d ca } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}