
rule Trojan_BAT_AgentTesla_EAY_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EAY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 04 11 08 07 11 08 91 09 61 08 11 05 91 61 28 ?? 00 00 0a 9c 11 05 1f 15 33 05 16 13 05 2b 06 11 05 17 58 13 05 11 08 17 58 13 08 11 08 07 8e 69 17 59 31 cb 12 04 07 8e 69 17 59 28 04 00 00 2b d0 53 00 00 01 28 } //2
		$a_01_1 = {53 00 69 00 6c 00 6c 00 65 00 61 00 6c 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //2 Silleal.Properties.Resources
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}