
rule Trojan_BAT_AgentTesla_NZO_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NZO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {08 11 07 09 11 07 09 8e 69 5d 91 08 11 07 91 61 9c 11 07 17 d6 13 07 11 07 11 06 31 e3 } //1
		$a_01_1 = {53 00 74 00 00 03 61 00 00 05 72 00 74 } //1
		$a_01_2 = {61 00 43 00 4b 00 5a 00 43 00 49 00 57 00 39 00 6b 00 6a 00 4a 00 46 00 53 00 49 00 4f 00 4a 00 39 00 30 00 } //1 aCKZCIW9kjJFSIOJ90
		$a_01_3 = {70 00 6f 00 73 00 74 00 69 00 6d 00 67 00 2e 00 63 00 63 00 2f 00 71 00 4d 00 6d 00 34 00 77 00 4b 00 38 00 70 00 } //1 postimg.cc/qMm4wK8p
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}