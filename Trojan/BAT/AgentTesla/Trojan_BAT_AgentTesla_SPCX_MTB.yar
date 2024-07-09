
rule Trojan_BAT_AgentTesla_SPCX_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.SPCX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {5d d4 91 28 ?? ?? ?? 0a 59 20 00 01 00 00 58 20 00 01 00 00 5d 28 ?? ?? ?? 0a 9c 11 05 17 6a 58 13 05 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}