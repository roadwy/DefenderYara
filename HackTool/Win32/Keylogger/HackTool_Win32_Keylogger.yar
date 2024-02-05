
rule HackTool_Win32_Keylogger{
	meta:
		description = "HackTool:Win32/Keylogger,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_80_0 = {48 65 78 4c 6f 67 67 65 72 } //HexLogger  01 00 
		$a_80_1 = {68 74 74 70 3a 2f 2f 6b 75 72 64 6f 6a 61 6e 2e 74 72 2e 67 67 2f } //http://kurdojan.tr.gg/  01 00 
		$a_00_2 = {73 00 65 00 6e 00 64 00 75 00 73 00 69 00 6e 00 67 00 00 00 } //01 00 
		$a_00_3 = {73 00 65 00 6e 00 64 00 70 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 00 00 } //01 00 
		$a_00_4 = {4d 00 61 00 69 00 6c 00 20 00 4f 00 72 00 67 00 61 00 6e 00 74 00 69 00 6f 00 6e 00 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}