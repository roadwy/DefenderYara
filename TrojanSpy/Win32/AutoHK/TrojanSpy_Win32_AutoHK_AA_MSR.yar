
rule TrojanSpy_Win32_AutoHK_AA_MSR{
	meta:
		description = "TrojanSpy:Win32/AutoHK.AA!MSR,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_02_0 = {73 69 74 65 20 3d 20 68 74 74 70 90 02 01 3a 2f 2f 32 6e 6f 2e 63 6f 90 00 } //01 00 
		$a_02_1 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 2c 20 90 02 32 2e 65 78 65 2c 20 90 02 0e 2e 65 78 65 90 00 } //01 00 
		$a_02_2 = {52 75 6e 2c 20 90 02 0e 2e 65 78 65 2c 2c 20 55 73 65 45 72 72 6f 72 4c 65 76 65 6c 90 00 } //01 00 
		$a_00_3 = {41 00 75 00 74 00 6f 00 48 00 6f 00 74 00 6b 00 65 00 79 00 2e 00 65 00 78 00 65 00 } //01 00  AutoHotkey.exe
		$a_00_4 = {57 00 69 00 6e 00 64 00 6f 00 77 00 53 00 70 00 79 00 2e 00 61 00 68 00 6b 00 } //00 00  WindowSpy.ahk
	condition:
		any of ($a_*)
 
}