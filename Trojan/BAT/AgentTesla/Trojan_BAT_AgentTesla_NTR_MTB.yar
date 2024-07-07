
rule Trojan_BAT_AgentTesla_NTR_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NTR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {20 00 01 00 00 0a 03 04 20 00 04 01 00 5d 03 02 20 00 04 01 00 04 28 90 01 03 06 03 04 17 58 20 00 04 01 00 5d 91 28 90 01 03 06 59 06 58 06 5d 28 90 01 03 06 9c 03 0b 2b 00 90 00 } //1
		$a_03_1 = {02 05 04 5d 91 03 05 1f 16 5d 6f 90 01 03 0a 61 28 90 01 03 06 0a 2b 00 06 2a 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Trojan_BAT_AgentTesla_NTR_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.NTR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {24 34 36 66 32 38 61 32 39 2d 38 30 63 30 2d 34 39 38 64 2d 62 64 66 34 2d 63 66 31 61 35 64 62 31 63 34 34 37 } //1 $46f28a29-80c0-498d-bdf4-cf1a5db1c447
		$a_01_1 = {43 6f 6d 75 6e 69 63 61 74 69 6f 6e 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 Comunication.Properties.Resources.resources
		$a_01_2 = {00 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 00 } //1
		$a_01_3 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerNonUserCodeAttribute
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}