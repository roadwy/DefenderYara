
rule Trojan_BAT_AgentTesla_YT_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.YT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0b 03 04 03 8e 69 5d 91 07 04 1f 16 5d 91 61 28 ?? ?? ?? 0a 03 04 17 58 03 8e 69 5d 91 28 ?? ?? ?? 0a 59 06 58 06 5d d2 0c 2b 00 08 2a } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}