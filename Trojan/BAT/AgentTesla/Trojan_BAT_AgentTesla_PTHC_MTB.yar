
rule Trojan_BAT_AgentTesla_PTHC_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PTHC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 1f 21 9d 28 ?? 00 00 06 0c 20 62 87 c3 6e 28 ?? 00 00 2b 28 80 00 00 06 20 19 4c 04 34 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}