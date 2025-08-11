
rule VirTool_Win32_InjectRemoteThread_NP{
	meta:
		description = "VirTool:Win32/InjectRemoteThread.NP,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_80_0 = {5c 70 68 6f 6e 65 68 6f 6d 65 2e 64 6c 6c } //\phonehome.dll  1
		$a_80_1 = {5c 74 65 6d 70 5c 73 62 } //\temp\sb  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1) >=2
 
}