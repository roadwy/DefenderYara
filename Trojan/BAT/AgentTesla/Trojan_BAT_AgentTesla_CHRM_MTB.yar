
rule Trojan_BAT_AgentTesla_CHRM_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.CHRM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 16 13 05 2b 27 00 09 11 04 11 05 28 ?? ?? ?? 06 13 07 11 07 28 ?? ?? ?? 0a 13 08 08 11 08 d2 6f ?? ?? ?? 0a 00 00 11 05 17 58 13 05 11 05 17 fe 04 13 09 11 09 2d ce 07 17 58 0b 00 11 04 17 58 13 04 11 04 20 00 72 00 00 fe 04 13 0a 11 0a 2d ae } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}