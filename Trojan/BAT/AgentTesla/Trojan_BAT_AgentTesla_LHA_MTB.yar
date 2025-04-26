
rule Trojan_BAT_AgentTesla_LHA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.LHA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 13 05 2b 4e 00 09 11 04 11 05 6f ?? ?? ?? 0a 13 06 09 11 04 11 05 6f ?? ?? ?? 0a 13 07 16 13 08 02 11 07 28 ?? ?? ?? 06 13 08 1b 13 09 11 09 13 0b 11 0b 13 0a 11 0a 1b 2e 02 2b 0d 17 13 0c 00 08 07 11 08 d2 9c 00 2b 02 2b 00 00 11 05 17 58 13 05 11 05 17 fe 04 13 0d 11 0d 2d } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}