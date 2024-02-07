
rule HackTool_Win32_Mimikatz_PA_{
	meta:
		description = "HackTool:Win32/Mimikatz.PA!!Mikatz.gen!D,SIGNATURE_TYPE_ARHSTR_EXT,0b 00 0b 00 03 00 00 0a 00 "
		
	strings :
		$a_00_0 = {6d 00 69 00 73 00 63 00 3a 00 3a 00 70 00 72 00 69 00 6e 00 74 00 6e 00 69 00 67 00 68 00 74 00 6d 00 61 00 72 00 65 00 } //01 00  misc::printnightmare
		$a_00_1 = {6c 00 69 00 62 00 72 00 61 00 72 00 79 00 3a 00 5c 00 5c 00 } //01 00  library:\\
		$a_00_2 = {73 00 65 00 72 00 76 00 65 00 72 00 3a 00 } //00 00  server:
	condition:
		any of ($a_*)
 
}