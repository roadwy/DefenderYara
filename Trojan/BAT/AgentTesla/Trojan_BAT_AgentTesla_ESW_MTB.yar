
rule Trojan_BAT_AgentTesla_ESW_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ESW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {20 00 01 00 00 0a 03 04 ?? ?? ?? ?? ?? 03 04 17 58 ?? ?? ?? ?? ?? 5d 91 ?? ?? ?? ?? ?? 59 06 58 06 5d 0b 03 04 ?? ?? ?? ?? ?? 5d 07 d2 9c 03 0c 2b 00 } //1
		$a_03_1 = {91 0b 07 06 03 1f 16 5d 6f ?? ?? ?? 0a 61 0c 2b 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}