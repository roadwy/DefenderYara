
rule VirTool_Win32_VBInject{
	meta:
		description = "VirTool:Win32/VBInject,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {4d 00 33 00 4e 00 33 00 47 00 40 00 54 00 54 00 31 00 } //1 M3N3G@TT1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule VirTool_Win32_VBInject_2{
	meta:
		description = "VirTool:Win32/VBInject,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {4d 52 75 6e 50 45 } //1 MRunPE
		$a_03_1 = {2e 00 65 00 58 00 65 [0-10] 3c 00 3c 00 35 00 30 00 43 00 45 00 4e 00 54 00 3d 00 47 00 2d 00 55 00 4e 00 49 00 54 00 3e 00 3e } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}