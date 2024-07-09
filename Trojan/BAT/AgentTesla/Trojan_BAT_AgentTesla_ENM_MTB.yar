
rule Trojan_BAT_AgentTesla_ENM_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ENM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 11 04 20 00 14 01 00 5d 07 11 04 20 00 14 01 00 5d 91 08 11 04 1f 16 5d 6f ?? ?? ?? 0a 61 28 ?? ?? ?? 0a 07 11 04 17 58 20 00 14 01 00 5d 91 28 ?? ?? ?? 0a 59 20 00 01 00 00 58 20 00 01 00 00 5d d2 9c 00 11 04 15 58 13 04 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}