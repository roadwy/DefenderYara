
rule HackTool_Win32_SmbAgent_J_ibt{
	meta:
		description = "HackTool:Win32/SmbAgent.J!ibt,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {06 02 20 bd 01 00 00 6f 05 00 00 0a 00 } //01 00 
		$a_00_1 = {06 19 91 06 18 91 20 00 01 00 00 5a 58 06 19 91 20 00 00 01 00 5a 58 0b 07 1a 58 8d 0b 00 00 01 } //01 00 
		$a_02_2 = {3a 5c 57 69 6e 64 6f 77 73 5c 54 65 6d 70 5c 90 01 08 2e 70 64 62 00 90 00 } //01 00 
		$a_00_3 = {50 69 6e 67 43 61 73 74 6c 65 2e 53 63 61 6e 6e 65 72 73 } //01 00 
		$a_00_4 = {52 65 61 64 53 6d 62 52 65 73 70 6f 6e 73 65 } //01 00 
		$a_00_5 = {6d 31 37 73 63 } //00 00 
	condition:
		any of ($a_*)
 
}