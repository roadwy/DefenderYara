
rule Trojan_BAT_AgentTesla_MBWD_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBWD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {02 06 07 6f ?? 00 00 0a 0c 04 03 6f ?? 00 00 0a 59 0d 09 13 ?? 11 ?? 19 32 } //2
		$a_01_1 = {4c 00 6f 00 61 00 64 } //1
		$a_01_2 = {79 00 73 00 74 00 65 00 6d 00 2e 00 41 00 63 00 74 00 69 00 76 00 61 00 74 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}
rule Trojan_BAT_AgentTesla_MBWD_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.MBWD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {60 0c 03 19 8d ?? ?? ?? 01 25 16 08 1f 10 63 20 ?? 00 00 00 5f d2 9c 25 17 08 1e } //2
		$a_01_1 = {4b 76 69 73 6b 6f 74 65 6b 61 2e 50 72 6f 70 65 72 74 69 65 73 } //1 Kviskoteka.Properties
		$a_01_2 = {47 00 65 00 74 00 45 00 78 00 70 00 6f 00 72 00 74 00 65 00 64 00 54 00 79 00 70 00 65 00 73 00 } //1 GetExportedTypes
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}