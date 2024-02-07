
rule HackTool_Win32_PortTransfer{
	meta:
		description = "HackTool:Win32/PortTransfer,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {41 63 63 65 70 74 20 61 20 43 6f 6e 6e 65 63 74 69 6f 6e 20 46 72 6f 6d 20 4c 65 66 74 } //01 00  Accept a Connection From Left
		$a_01_1 = {50 6f 72 74 54 72 61 6e 73 66 65 72 2e 65 78 65 } //01 00  PortTransfer.exe
		$a_01_2 = {43 6f 64 65 64 20 62 79 20 62 6c 61 63 6b 73 70 6c 69 74 } //01 00  Coded by blacksplit
		$a_01_3 = {50 6f 72 74 54 72 61 6e 73 66 65 72 5c 52 65 6c 65 61 73 65 5c 50 6f 72 74 54 72 61 6e 73 66 65 72 2e 70 64 62 } //01 00  PortTransfer\Release\PortTransfer.pdb
		$a_01_4 = {43 72 65 61 74 65 20 54 68 72 65 61 64 20 53 75 63 63 65 73 73 2e } //00 00  Create Thread Success.
		$a_00_5 = {5d 04 00 } //00 b3 
	condition:
		any of ($a_*)
 
}