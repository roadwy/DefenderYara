
rule TrojanDropper_Win32_Spiloog_A_bit{
	meta:
		description = "TrojanDropper:Win32/Spiloog.A!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 76 63 68 6f 73 74 64 2e 65 78 65 } //01 00  svchostd.exe
		$a_01_1 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //01 00  Software\Microsoft\Windows\CurrentVersion\Run
		$a_01_2 = {53 4f 46 54 57 41 52 45 5c 41 56 44 5f 61 6e 76 69 72 5f 73 79 73 } //00 00  SOFTWARE\AVD_anvir_sys
	condition:
		any of ($a_*)
 
}