
rule Trojan_BAT_AgentTesla_PTDC_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PTDC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {73 3d 00 00 06 0a 06 03 7d 44 00 00 04 02 06 fe 06 3e 00 00 06 73 54 00 00 0a 28 ?? 00 00 2b 28 ?? 00 00 2b 2a } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}