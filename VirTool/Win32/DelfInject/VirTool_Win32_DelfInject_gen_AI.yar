
rule VirTool_Win32_DelfInject_gen_AI{
	meta:
		description = "VirTool:Win32/DelfInject.gen!AI,SIGNATURE_TYPE_PEHSTR,09 00 09 00 0c 00 00 01 00 "
		
	strings :
		$a_01_0 = {6c 6c 64 2e 32 33 6c 65 6e 72 65 6b } //01 00  lld.23lenrek
		$a_01_1 = {41 65 6d 61 4e 65 6c 69 46 65 6c 75 64 6f 4d 74 65 47 } //01 00  AemaNeliFeludoMteG
		$a_01_2 = {65 63 72 75 6f 73 65 52 66 6f 65 7a 69 53 } //01 00  ecruoseRfoeziS
		$a_01_3 = {41 65 63 72 75 6f 73 65 52 64 6e 69 46 } //01 00  AecruoseRdniF
		$a_01_4 = {65 63 72 75 6f 73 65 52 64 61 6f 4c } //01 00  ecruoseRdaoL
		$a_01_5 = {65 63 72 75 6f 73 65 52 6b 63 6f 4c } //01 00  ecruoseRkcoL
		$a_01_6 = {65 63 72 75 6f 73 65 52 65 65 72 46 } //01 00  ecruoseReerF
		$a_01_7 = {31 61 74 61 64 } //01 00  1atad
		$a_01_8 = {73 74 61 72 74 73 74 65 61 6c } //01 00  startsteal
		$a_01_9 = {6c 61 65 74 73 74 72 61 74 73 } //01 00  laetstrats
		$a_01_10 = {50 00 42 00 44 00 41 00 54 00 41 00 } //01 00  PBDATA
		$a_01_11 = {44 00 41 00 54 00 41 00 31 00 } //00 00  DATA1
	condition:
		any of ($a_*)
 
}