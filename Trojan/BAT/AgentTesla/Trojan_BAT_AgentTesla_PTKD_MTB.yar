
rule Trojan_BAT_AgentTesla_PTKD_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PTKD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {6f cd 00 00 0a 28 ?? 00 00 0a d0 13 00 00 02 28 ?? 00 00 0a 6f cf 00 00 0a 28 ?? 00 00 06 6f 3d 00 00 0a 73 3e 00 00 0a 0d } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}