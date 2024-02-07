
rule HackTool_Win32_Wrokni_C{
	meta:
		description = "HackTool:Win32/Wrokni.C,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 0a 00 "
		
	strings :
		$a_01_0 = {68 5f 4c 45 5f } //01 00  h_LE_
		$a_00_1 = {42 00 75 00 67 00 53 00 69 00 67 00 6e 00 61 00 74 00 75 00 72 00 65 00 } //01 00  BugSignature
		$a_00_2 = {56 00 69 00 64 00 65 00 6f 00 44 00 72 00 69 00 76 00 65 00 72 00 20 00 73 00 65 00 72 00 76 00 69 00 63 00 65 00 } //00 00  VideoDriver service
	condition:
		any of ($a_*)
 
}