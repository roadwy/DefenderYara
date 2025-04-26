
rule VirTool_Win32_Vbinder_AW{
	meta:
		description = "VirTool:Win32/Vbinder.AW,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {42 00 65 00 74 00 61 00 20 00 43 00 72 00 79 00 70 00 74 00 65 00 72 00 5c 00 53 00 74 00 75 00 62 00 5c 00 50 00 72 00 6f 00 6a 00 65 00 6b 00 74 00 31 00 2e 00 76 00 62 00 70 00 00 00 } //1
		$a_01_1 = {4d 6f 64 75 6c 65 31 00 4d 6f 64 75 6c 65 32 00 48 55 4e 54 57 55 56 4a 55 41 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}