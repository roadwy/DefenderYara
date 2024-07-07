
rule HackTool_Win64_JuicyPotato_SBR_MSR{
	meta:
		description = "HackTool:Win64/JuicyPotato.SBR!MSR,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {4a 75 69 63 79 50 6f 74 61 74 6f 2e 70 64 62 } //1 JuicyPotato.pdb
		$a_01_1 = {57 61 69 74 69 6e 67 20 66 6f 72 20 61 75 74 68 } //1 Waiting for auth
		$a_01_2 = {73 68 75 74 64 6f 77 6e } //1 shutdown
		$a_01_3 = {41 71 75 69 72 65 43 72 65 64 65 6e 74 69 61 6c } //1 AquireCredential
		$a_01_4 = {68 00 65 00 6c 00 6c 00 6f 00 2e 00 73 00 74 00 67 00 } //1 hello.stg
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}