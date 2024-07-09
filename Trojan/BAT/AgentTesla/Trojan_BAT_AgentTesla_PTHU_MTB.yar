
rule Trojan_BAT_AgentTesla_PTHU_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PTHU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {72 bd 00 00 70 28 ?? 00 00 06 28 ?? 00 00 06 fe 0c 01 00 6f 28 00 00 0a } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}