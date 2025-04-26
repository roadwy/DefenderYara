
rule Trojan_BAT_AgentTesla_WIMB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.WIMB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 13 05 2b 29 00 09 11 04 11 05 6f ?? ?? ?? 0a 13 06 11 06 28 ?? ?? ?? 0a 13 07 08 11 04 11 07 d2 6f ?? ?? ?? 0a 00 00 11 05 17 58 13 05 11 05 17 fe 04 13 08 11 08 2d cc 07 17 58 0b 00 11 04 17 58 13 04 11 04 20 00 56 00 00 fe 04 13 09 11 09 2d ac } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}