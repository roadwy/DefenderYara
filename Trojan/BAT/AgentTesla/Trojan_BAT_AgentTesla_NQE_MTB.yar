
rule Trojan_BAT_AgentTesla_NQE_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NQE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {42 6f 67 67 6c 65 53 65 72 76 65 72 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 BoggleServer.Properties.Resources.resources
		$a_01_1 = {24 65 61 30 64 61 64 38 62 2d 38 38 38 32 2d 34 31 33 35 2d 62 31 31 62 2d 61 38 32 39 36 35 34 66 37 33 34 66 } //1 $ea0dad8b-8882-4135-b11b-a829654f734f
		$a_01_2 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 53 74 61 74 65 } //1 DebuggerBrowsableState
		$a_01_3 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerNonUserCodeAttribute
		$a_01_4 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerBrowsableAttribute
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}