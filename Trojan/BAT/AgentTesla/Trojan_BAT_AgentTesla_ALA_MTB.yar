
rule Trojan_BAT_AgentTesla_ALA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ALA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {d2 0b 03 07 1f 1f 5f 64 28 ?? ?? ?? 0a 0c 02 1b 40 12 00 00 00 06 08 19 91 6f ?? ?? ?? 0a 06 08 18 91 6f ?? ?? ?? 0a 06 08 17 91 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}