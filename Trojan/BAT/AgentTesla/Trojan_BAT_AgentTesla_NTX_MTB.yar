
rule Trojan_BAT_AgentTesla_NTX_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NTX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {02 05 04 5d 91 03 05 1f 16 5d 28 90 01 04 61 90 00 } //1
		$a_01_1 = {66 33 36 64 39 33 31 37 64 61 30 65 } //1 f36d9317da0e
		$a_01_2 = {34 65 36 36 33 66 61 65 2d 39 31 64 65 } //1 4e663fae-91de
		$a_01_3 = {4f 76 65 72 73 69 6b 74 2e 50 72 6f 70 65 72 74 69 65 } //1 Oversikt.Propertie
		$a_01_4 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerNonUserCodeAttribute
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}