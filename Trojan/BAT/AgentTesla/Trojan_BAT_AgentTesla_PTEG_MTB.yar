
rule Trojan_BAT_AgentTesla_PTEG_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PTEG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 0e 06 09 28 ?? 00 00 0a 14 d0 04 00 00 02 28 ?? 00 00 0a 18 8d 23 00 00 01 25 16 16 14 28 ?? 00 00 0a a2 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}