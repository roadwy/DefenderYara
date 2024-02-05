
rule HackTool_Win32_Mimikatz_PTT_{
	meta:
		description = "HackTool:Win32/Mimikatz.PTT!!Mikatz.gen!D,SIGNATURE_TYPE_ARHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_00_0 = {6b 65 72 62 65 72 6f 73 3a 3a 70 74 74 20 90 02 40 40 } //00 00 
	condition:
		any of ($a_*)
 
}