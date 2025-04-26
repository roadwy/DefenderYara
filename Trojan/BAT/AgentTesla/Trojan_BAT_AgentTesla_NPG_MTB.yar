
rule Trojan_BAT_AgentTesla_NPG_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NPG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {5d 07 06 20 ?? ?? ?? 00 5d 91 08 06 1f 16 5d 6f ?? ?? ?? 0a 61 28 ?? ?? ?? 0a 07 06 17 58 20 ?? ?? ?? 00 5d 91 28 ?? ?? ?? 0a 59 20 ?? ?? ?? 00 58 20 ?? ?? ?? 00 5d d2 9c 06 15 58 0a 06 16 fe 04 16 fe 01 13 05 11 05 2d af } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}