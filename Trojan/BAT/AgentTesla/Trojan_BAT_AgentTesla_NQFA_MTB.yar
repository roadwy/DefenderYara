
rule Trojan_BAT_AgentTesla_NQFA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NQFA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 07 03 07 03 28 ?? ?? ?? 06 5d 6f ?? ?? ?? 0a 06 07 91 61 28 ?? ?? ?? 06 9c 00 07 17 58 0b 07 06 8e 69 fe 04 0c 08 2d d6 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}