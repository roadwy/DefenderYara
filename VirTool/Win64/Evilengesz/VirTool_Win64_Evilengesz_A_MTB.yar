
rule VirTool_Win64_Evilengesz_A_MTB{
	meta:
		description = "VirTool:Win64/Evilengesz.A!MTB,SIGNATURE_TYPE_PEHSTR,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {29 2e 61 64 64 4a 73 49 6e 6a 65 63 74 } //1 ).addJsInject
		$a_01_1 = {2e 73 6f 63 6b 73 41 75 74 68 4d 65 74 68 6f 64 } //1 .socksAuthMethod
		$a_01_2 = {29 2e 49 73 41 63 74 69 76 65 48 6f 73 74 6e 61 6d 65 } //1 ).IsActiveHostname
		$a_01_3 = {29 2e 67 65 74 50 69 76 6f 74 } //1 ).getPivot
		$a_01_4 = {29 2e 67 65 74 54 4c 53 43 65 72 74 69 66 69 63 61 74 65 } //1 ).getTLSCertificate
		$a_01_5 = {29 2e 45 6e 61 62 6c 65 50 72 6f 78 79 } //1 ).EnableProxy
		$a_01_6 = {29 2e 52 65 70 6f 72 74 43 72 65 64 65 6e 74 69 61 6c 73 53 75 62 6d 69 74 74 65 64 } //1 ).ReportCredentialsSubmitted
		$a_01_7 = {29 2e 47 65 74 53 63 72 69 70 74 49 6e 6a 65 63 74 } //1 ).GetScriptInject
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}