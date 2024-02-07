
rule VirTool_Win32_VBInject_UQ{
	meta:
		description = "VirTool:Win32/VBInject.UQ,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {3a 00 5c 00 43 00 6c 00 69 00 65 00 6e 00 74 00 20 00 73 00 68 00 69 00 74 00 5c 00 50 00 72 00 6f 00 6a 00 65 00 63 00 74 00 31 00 31 00 2e 00 76 00 62 00 70 00 } //01 00  :\Client shit\Project11.vbp
		$a_01_1 = {45 00 4c 00 50 00 55 00 54 00 4f 00 } //00 00  ELPUTO
	condition:
		any of ($a_*)
 
}