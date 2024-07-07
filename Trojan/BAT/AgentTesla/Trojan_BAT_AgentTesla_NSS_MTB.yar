
rule Trojan_BAT_AgentTesla_NSS_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NSS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {28 1b 00 00 06 0a 28 90 01 01 00 00 0a 06 6f 90 01 01 00 00 0a 28 90 01 01 00 00 0a 28 90 01 01 00 00 06 0b dd 03 90 00 } //5
		$a_01_1 = {57 69 6e 64 6f 77 73 46 6f 72 6d 73 41 70 70 32 37 2e 50 72 6f 70 65 72 74 69 65 73 } //1 WindowsFormsApp27.Properties
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}
rule Trojan_BAT_AgentTesla_NSS_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.NSS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {00 08 11 05 07 11 05 18 5a 18 28 90 01 03 06 1f 10 28 90 01 03 06 9c 00 11 05 17 58 13 05 11 05 08 8e 69 fe 04 13 06 11 06 2d d5 90 00 } //1
		$a_01_1 = {31 38 62 35 2d 62 65 65 65 2d 34 32 30 31 2d 62 35 61 30 2d 38 62 37 38 35 34 65 } //1 18b5-beee-4201-b5a0-8b7854e
		$a_01_2 = {53 75 62 73 74 72 69 6e 67 } //1 Substring
		$a_01_3 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerNonUserCodeAttribute
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}