
rule HackTool_Win32_Mimikatz_F_{
	meta:
		description = "HackTool:Win32/Mimikatz.F!!Mikatz.gen!F,SIGNATURE_TYPE_ARHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_80_0 = {73 65 6b 75 72 6c 73 61 3a 3a 6c 6f 67 6f 6e 70 61 73 73 77 6f 72 64 73 20 65 78 69 74 } //sekurlsa::logonpasswords exit  1
	condition:
		((#a_80_0  & 1)*1) >=1
 
}