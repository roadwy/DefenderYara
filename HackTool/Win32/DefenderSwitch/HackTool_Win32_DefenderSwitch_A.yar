
rule HackTool_Win32_DefenderSwitch_A{
	meta:
		description = "HackTool:Win32/DefenderSwitch.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_80_0 = {44 65 66 65 6e 64 65 72 53 77 69 74 63 68 2e 70 64 62 } //DefenderSwitch.pdb  01 00 
		$a_80_1 = {43 6f 75 6c 64 6e 27 74 20 73 74 6f 70 20 57 69 6e 44 65 66 65 6e 64 20 73 65 72 76 69 63 65 } //Couldn't stop WinDefend service  01 00 
		$a_80_2 = {54 72 79 69 6e 67 20 74 6f 20 73 74 6f 70 20 57 69 6e 64 6f 77 73 20 44 65 66 65 6e 64 65 72 } //Trying to stop Windows Defender  01 00 
		$a_80_3 = {55 73 61 67 65 3a 20 2e 5c 44 65 66 65 6e 64 65 72 53 77 69 74 63 68 2e 65 78 65 20 5b 2d 6f 6e 7c 2d 6f 66 66 5d } //Usage: .\DefenderSwitch.exe [-on|-off]  00 00 
	condition:
		any of ($a_*)
 
}