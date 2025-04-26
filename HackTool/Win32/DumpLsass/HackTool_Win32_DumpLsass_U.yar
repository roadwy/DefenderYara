
rule HackTool_Win32_DumpLsass_U{
	meta:
		description = "HackTool:Win32/DumpLsass.U,SIGNATURE_TYPE_PEHSTR_EXT,ffffffc8 00 ffffffc8 00 02 00 00 "
		
	strings :
		$a_80_0 = {4c 73 61 73 73 53 69 6c 65 6e 74 50 72 6f 63 65 73 73 45 78 69 74 } //LsassSilentProcessExit  100
		$a_80_1 = {3c 4c 53 41 53 53 5f 50 49 44 3e } //<LSASS_PID>  100
	condition:
		((#a_80_0  & 1)*100+(#a_80_1  & 1)*100) >=200
 
}