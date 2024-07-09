
rule Trojan_BAT_AgentTesla_MIL_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MIL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {18 9a 0c 08 6f ?? ?? ?? ?? 18 9a 0d 09 14 17 8d ?? ?? ?? ?? 25 16 07 6f ?? ?? ?? ?? a2 6f ?? ?? ?? ?? 26 1f 37 90 09 07 00 0b 06 6f } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}