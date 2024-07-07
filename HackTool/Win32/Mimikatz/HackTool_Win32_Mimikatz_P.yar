
rule HackTool_Win32_Mimikatz_P{
	meta:
		description = "HackTool:Win32/Mimikatz.P,SIGNATURE_TYPE_CMDHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_00_0 = {6d 00 69 00 73 00 63 00 3a 00 3a 00 70 00 72 00 69 00 6e 00 74 00 6e 00 69 00 67 00 68 00 74 00 6d 00 61 00 72 00 65 00 } //3 misc::printnightmare
		$a_00_1 = {6c 00 69 00 62 00 72 00 61 00 72 00 79 00 3a 00 } //1 library:
		$a_00_2 = {73 00 65 00 72 00 76 00 65 00 72 00 3a 00 } //1 server:
	condition:
		((#a_00_0  & 1)*3+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=4
 
}