
rule Backdoor_Win32_Xtrat_H{
	meta:
		description = "Backdoor:Win32/Xtrat.H,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {58 00 54 00 52 00 45 00 4d 00 45 00 42 00 49 00 4e 00 44 00 45 00 52 00 } //01 00  XTREMEBINDER
		$a_01_1 = {4e 00 4f 00 49 00 4e 00 4a 00 45 00 43 00 54 00 25 00 } //01 00  NOINJECT%
		$a_01_2 = {5b 00 42 00 61 00 63 00 6b 00 73 00 70 00 61 00 63 00 65 00 5d 00 } //01 00  [Backspace]
		$a_00_3 = {5b 00 50 00 72 00 6f 00 63 00 65 00 73 00 73 00 5d 00 } //01 00  [Process]
		$a_00_4 = {53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 46 00 61 00 6b 00 65 00 4d 00 65 00 73 00 73 00 61 00 67 00 65 00 } //00 00  SOFTWARE\FakeMessage
	condition:
		any of ($a_*)
 
}