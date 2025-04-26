
rule Trojan_BAT_AgentTesla_NSJ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NSJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {08 07 09 20 00 c4 00 00 28 ?? ?? ?? 06 0b 09 15 58 0d 09 16 fe 04 16 fe 01 13 04 11 04 2d e1 } //1
		$a_03_1 = {03 04 05 5d 03 04 05 5d 91 02 04 1f 16 5d 6f ?? ?? ?? 0a 61 28 ?? ?? ?? 06 03 04 17 58 05 5d 91 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}