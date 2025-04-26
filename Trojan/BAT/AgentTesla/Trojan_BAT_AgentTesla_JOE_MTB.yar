
rule Trojan_BAT_AgentTesla_JOE_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.JOE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 07 06 09 18 5a 18 6f ?? ?? ?? 0a 1f 10 28 ?? ?? ?? 0a d2 6f ?? ?? ?? 0a 00 00 09 17 58 0d 09 06 6f ?? ?? ?? 0a 18 5b fe 04 13 04 11 04 2d d0 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}