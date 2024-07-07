
rule Trojan_BAT_AgentTesla_MBHN_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBHN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {20 00 46 0b 00 0c 07 73 90 01 01 00 00 0a 0d 09 16 73 90 01 01 00 00 0a 13 04 08 8d 90 01 01 00 00 01 13 05 11 04 11 05 16 08 90 00 } //1
		$a_01_1 = {33 2e 67 2e 72 65 73 6f 75 72 63 65 73 } //1 3.g.resources
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}