
rule HackTool_Win32_DumpLsass_X{
	meta:
		description = "HackTool:Win32/DumpLsass.X,SIGNATURE_TYPE_CMDHSTR_EXT,14 00 14 00 02 00 00 0a 00 "
		
	strings :
		$a_00_0 = {3a 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 57 00 65 00 72 00 46 00 61 00 75 00 6c 00 74 00 2e 00 65 00 78 00 65 00 20 00 2d 00 73 00 20 00 2d 00 74 00 20 00 } //0a 00  :\Windows\system32\WerFault.exe -s -t 
		$a_00_1 = {20 00 2d 00 65 00 20 00 } //00 00   -e 
	condition:
		any of ($a_*)
 
}