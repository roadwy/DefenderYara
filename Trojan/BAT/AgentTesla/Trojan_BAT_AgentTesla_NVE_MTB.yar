
rule Trojan_BAT_AgentTesla_NVE_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NVE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {57 1d a2 0b 09 1f 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 68 00 00 00 12 00 00 00 d2 02 00 00 8c 05 00 00 ce 02 00 00 b5 00 00 00 01 00 00 00 b5 } //1
		$a_01_1 = {50 75 72 76 69 6c 65 2e 52 65 73 6f 75 72 63 65 73 2e 72 } //1 Purvile.Resources.r
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Trojan_BAT_AgentTesla_NVE_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.NVE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_03_0 = {6f 38 00 00 0a 25 26 26 11 0a 11 0d 16 06 6f ?? ?? ?? 0a 25 26 11 0e 6a 59 69 6f ?? ?? ?? 0a 25 26 13 10 7e ?? ?? ?? 04 11 10 16 11 10 28 ?? ?? ?? 06 25 26 69 6f ?? ?? ?? 0a } //5
		$a_01_1 = {42 56 4e 42 4d 48 4a 47 } //1 BVNBMHJG
		$a_01_2 = {61 64 64 5f 52 65 73 6f 75 72 63 65 52 65 73 6f 6c 76 65 } //1 add_ResourceResolve
		$a_01_3 = {50 72 6f 63 65 73 73 49 6e 66 6f 72 6d 61 74 69 6f 6e 43 6c 61 73 73 } //1 ProcessInformationClass
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=8
 
}