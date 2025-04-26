
rule Trojan_BAT_AgentTesla_ABQW_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABQW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 08 02 8e 69 5d 02 08 02 8e 69 5d 91 07 08 07 8e 69 5d 91 61 28 ?? ?? ?? 0a 02 08 1e 58 1d 59 02 8e 69 5d 91 59 20 ?? ?? ?? 00 58 18 58 20 ?? ?? ?? 00 5d d2 9c 08 16 2d 02 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}