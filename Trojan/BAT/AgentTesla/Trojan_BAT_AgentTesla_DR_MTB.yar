
rule Trojan_BAT_AgentTesla_DR_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.DR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {a2 06 18 72 ?? 0d 00 70 a2 28 5d 00 00 06 0b 07 72 ?? 0d 00 70 72 ?? 0d 00 70 6f ?? ?? ?? 0a 0c 08 28 6a 00 00 06 0d 09 28 ?? ?? ?? 0a 13 04 11 04 6f ?? ?? ?? 0a } //1
		$a_03_1 = {16 9a 13 05 11 05 72 ?? 0d 00 70 6f ?? ?? ?? 0a 13 06 11 06 16 8c ?? ?? ?? 01 06 6f ?? ?? ?? 0a 26 16 28 ?? ?? ?? 0a 00 72 ?? 0d 00 70 13 07 2b 00 11 07 2a } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}