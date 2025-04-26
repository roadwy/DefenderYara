
rule Trojan_BAT_AgentTesla_PTFK_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PTFK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {75 3c 00 00 01 28 ?? 00 00 06 28 ?? 00 00 06 28 ?? 00 00 2b 28 ?? 00 00 06 14 1a d0 16 00 00 02 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}