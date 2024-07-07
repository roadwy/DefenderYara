
rule HackTool_Win32_DumpLsass_Z{
	meta:
		description = "HackTool:Win32/DumpLsass.Z,SIGNATURE_TYPE_CMDHSTR_EXT,28 00 28 00 04 00 00 "
		
	strings :
		$a_00_0 = {3a 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 57 00 65 00 72 00 46 00 61 00 75 00 6c 00 74 00 2e 00 65 00 78 00 65 00 20 00 2d 00 75 00 } //10 :\Windows\system32\WerFault.exe -u
		$a_00_1 = {20 00 2d 00 70 00 20 00 } //10  -p 
		$a_00_2 = {20 00 2d 00 69 00 70 00 20 00 } //10  -ip 
		$a_00_3 = {20 00 2d 00 73 00 20 00 } //10  -s 
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10+(#a_00_3  & 1)*10) >=40
 
}