
rule Trojan_BAT_AgentTesla_ASEZ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ASEZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 00 11 01 02 11 01 91 72 ?? 00 00 70 28 ?? 00 00 06 59 d2 9c 20 02 00 00 00 38 ?? ff ff ff 11 01 17 58 13 01 20 06 00 00 00 38 } //1
		$a_01_1 = {59 75 79 66 69 7a 65 61 7a 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //1 Yuyfizeaz.Properties.Resources
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}