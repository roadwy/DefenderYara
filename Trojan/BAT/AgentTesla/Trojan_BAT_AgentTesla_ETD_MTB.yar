
rule Trojan_BAT_AgentTesla_ETD_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ETD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {03 04 17 58 ?? ?? ?? ?? ?? 5d 91 28 3f 00 00 0a 59 05 58 05 5d 0a 03 04 ?? ?? ?? ?? ?? 5d 06 d2 9c 03 0b 2b 00 } //1
		$a_03_1 = {5d 91 0a 06 7e ?? ?? ?? 04 03 1f 16 5d 6f ?? ?? ?? 0a 61 0b 2b 00 07 2a } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}