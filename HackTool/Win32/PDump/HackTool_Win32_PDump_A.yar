
rule HackTool_Win32_PDump_A{
	meta:
		description = "HackTool:Win32/PDump.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_80_0 = {5c 47 4c 4f 42 41 4c 3f 3f 5c 4b 6e 6f 77 6e 44 6c 6c 73 } //\GLOBAL??\KnownDlls  1
		$a_00_1 = {44 65 66 69 6e 65 44 6f 73 44 65 76 69 63 65 57 } //1 DefineDosDeviceW
	condition:
		((#a_80_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}