
rule Trojan_BAT_AgentTesla_PSJN_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSJN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {08 20 cc 48 3c f9 28 ?? ?? ?? 06 6f ?? ?? ?? 0a 74 ?? ?? ?? 1b 0b 07 8e 69 8d 0b 00 00 01 13 04 16 0a 2b 14 11 04 06 07 06 91 09 06 09 8e 69 5d 91 61 d2 9c 06 17 58 0a 06 07 8e 69 32 e6 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}