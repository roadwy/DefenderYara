
rule Trojan_BAT_AgentTesla_EPO_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EPO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {06 07 02 07 91 03 07 03 6f ?? ?? ?? 0a 5d 6f ?? ?? ?? 0a 61 d2 9c 00 07 17 58 0b } //1
		$a_01_1 = {40 00 40 00 40 00 40 00 40 00 40 00 40 00 40 00 4c 00 40 00 40 00 40 00 40 00 40 00 40 00 40 00 40 00 40 00 40 00 40 00 40 00 40 00 40 00 6f 00 40 00 40 00 40 00 40 00 40 00 40 00 40 00 40 00 40 00 40 00 40 00 40 00 40 00 61 00 40 00 40 00 40 00 40 00 40 00 40 00 40 00 40 00 40 00 64 00 40 00 40 00 40 00 40 00 40 00 40 00 40 00 } //1 @@@@@@@@L@@@@@@@@@@@@@@o@@@@@@@@@@@@@a@@@@@@@@@d@@@@@@@
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}