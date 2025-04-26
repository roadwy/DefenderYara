
rule Trojan_BAT_AgentTesla_EOM_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EOM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {20 00 01 00 00 0d 06 20 00 56 00 00 5d 13 04 07 11 04 91 08 06 1f 16 5d 6f ?? ?? ?? 0a 61 28 ?? ?? ?? 0a 13 06 07 06 19 58 18 59 20 00 56 00 00 5d 91 28 ?? ?? ?? 0a } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}