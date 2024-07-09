
rule Trojan_BAT_AgentTesla_PTHD_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PTHD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {1f 61 6a 08 28 ?? 00 00 06 80 08 00 00 04 20 09 00 00 00 17 3a 99 00 00 00 26 28 ?? 00 00 06 25 26 06 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}