
rule VirTool_Win32_DumpHive_B{
	meta:
		description = "VirTool:Win32/DumpHive.B,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_00_0 = {20 00 73 00 61 00 76 00 65 00 20 00 68 00 6b 00 6c 00 6d 00 5c 00 73 00 61 00 6d 00 20 00 } //1  save hklm\sam 
		$a_00_1 = {20 00 73 00 61 00 76 00 65 00 20 00 48 00 4b 00 45 00 59 00 5f 00 4c 00 4f 00 43 00 41 00 4c 00 5f 00 4d 00 41 00 43 00 48 00 49 00 4e 00 45 00 5c 00 73 00 61 00 6d 00 20 00 } //1  save HKEY_LOCAL_MACHINE\sam 
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=1
 
}
rule VirTool_Win32_DumpHive_B_2{
	meta:
		description = "VirTool:Win32/DumpHive.B,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_00_0 = {20 00 73 00 61 00 76 00 65 00 20 00 68 00 6b 00 6c 00 6d 00 5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 20 00 } //1  save hklm\system 
		$a_00_1 = {20 00 73 00 61 00 76 00 65 00 20 00 48 00 4b 00 45 00 59 00 5f 00 4c 00 4f 00 43 00 41 00 4c 00 5f 00 4d 00 41 00 43 00 48 00 49 00 4e 00 45 00 5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 20 00 } //1  save HKEY_LOCAL_MACHINE\system 
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=1
 
}
rule VirTool_Win32_DumpHive_B_3{
	meta:
		description = "VirTool:Win32/DumpHive.B,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_00_0 = {20 00 73 00 61 00 76 00 65 00 20 00 68 00 6b 00 6c 00 6d 00 5c 00 73 00 65 00 63 00 75 00 72 00 69 00 74 00 79 00 20 00 } //1  save hklm\security 
		$a_00_1 = {20 00 73 00 61 00 76 00 65 00 20 00 48 00 4b 00 45 00 59 00 5f 00 4c 00 4f 00 43 00 41 00 4c 00 5f 00 4d 00 41 00 43 00 48 00 49 00 4e 00 45 00 5c 00 73 00 65 00 63 00 75 00 72 00 69 00 74 00 79 00 20 00 } //1  save HKEY_LOCAL_MACHINE\security 
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=1
 
}