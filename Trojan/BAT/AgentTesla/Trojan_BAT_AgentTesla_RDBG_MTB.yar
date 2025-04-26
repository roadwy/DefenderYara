
rule Trojan_BAT_AgentTesla_RDBG_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.RDBG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 17 58 11 ?? 5d 13 ?? 07 06 91 11 ?? 61 07 11 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}