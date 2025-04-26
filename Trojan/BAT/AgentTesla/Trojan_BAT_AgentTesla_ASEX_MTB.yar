
rule Trojan_BAT_AgentTesla_ASEX_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ASEX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {07 06 8e 69 5d 13 05 07 11 04 6f ?? 00 00 0a 5d 13 09 06 11 05 91 13 0a 11 04 11 09 6f ?? 00 00 0a 13 0b 02 } //1
		$a_03_1 = {11 0a 11 0b 11 0c 28 ?? 00 00 06 13 0d 06 11 05 02 11 0d 28 ?? 00 00 06 9c 07 17 59 0b 07 16 fe 04 16 fe 01 13 0e 11 0e 2d } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}