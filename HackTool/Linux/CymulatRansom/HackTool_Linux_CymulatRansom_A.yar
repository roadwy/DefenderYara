
rule HackTool_Linux_CymulatRansom_A{
	meta:
		description = "HackTool:Linux/CymulatRansom.A,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_80_0 = {25 73 2f 45 6e 63 72 79 70 74 65 64 46 69 6c 65 73 } //%s/EncryptedFiles  1
		$a_80_1 = {2e 43 79 6d 43 72 79 70 74 } //.CymCrypt  1
		$a_80_2 = {45 72 72 6f 72 3a 20 43 79 6d 75 6c 61 74 65 4c 69 6e 75 78 52 61 6e 73 6f 6d 77 61 72 65 } //Error: CymulateLinuxRansomware  1
		$a_80_3 = {43 79 6d 75 6c 61 74 65 45 44 52 53 63 65 6e 61 72 69 6f 45 78 65 63 75 74 6f 72 } //CymulateEDRScenarioExecutor  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=4
 
}