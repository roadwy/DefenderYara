
rule Trojan_BAT_AgentTesla_AAH_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AAH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 0d 06 16 99 13 04 2b 5d 00 09 17 58 0d 11 04 23 00 00 00 00 00 00 59 40 5a 28 ?? ?? ?? 0a 69 13 05 11 04 06 07 1b 28 ?? ?? ?? 06 23 00 00 00 00 00 00 59 40 5a 28 ?? ?? ?? 0a 69 13 06 02 7b 01 00 00 04 28 ?? ?? ?? 0a 73 11 00 00 0a 11 05 11 06 1b 1b 73 12 00 00 0a 6f ?? ?? ?? 0a 00 00 11 04 08 58 13 04 11 04 06 1a 99 08 58 fe 03 16 fe 01 13 07 11 07 2d 91 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}