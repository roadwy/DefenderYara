
rule Trojan_BAT_AgentTesla_JRN_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.JRN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {09 11 04 9a 13 05 11 05 28 90 01 03 0a 23 90 01 08 59 28 90 01 03 0a b7 13 06 07 11 06 28 90 01 03 0a 28 90 01 03 0a 28 90 01 03 0a 0b 00 11 04 17 d6 13 04 11 04 09 8e 69 fe 04 13 07 11 07 2d ba 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_AgentTesla_JRN_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.JRN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {0a 0b 09 28 90 01 03 0a 03 6f 90 01 03 0a 6f 90 01 03 0a 13 04 06 11 04 6f 90 01 03 0a 06 18 6f 90 01 03 0a 02 28 90 01 03 0a 0c 28 90 01 03 0a 06 6f 90 01 03 0a 08 16 08 8e 69 6f 90 01 03 0a 6f 90 01 03 0a 0b 07 13 05 11 05 90 00 } //1
		$a_01_1 = {24 30 62 63 65 65 66 32 65 2d 63 36 64 37 2d 34 34 30 31 2d 38 35 66 37 2d 38 64 30 63 64 37 61 61 37 34 31 36 } //1 $0bceef2e-c6d7-4401-85f7-8d0cd7aa7416
		$a_81_2 = {53 65 72 76 69 63 65 4d 61 6e 61 67 65 72 } //1 ServiceManager
		$a_81_3 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerNonUserCodeAttribute
		$a_81_4 = {56 65 6e 74 65 6c 6f } //1 Ventelo
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}