
rule TrojanSpy_Win32_Swisyn_F{
	meta:
		description = "TrojanSpy:Win32/Swisyn.F,SIGNATURE_TYPE_PEHSTR,03 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 77 77 77 2e 33 31 33 33 34 2e 69 6e 66 6f 2f 31 73 74 75 70 6c 6f 61 64 2e 70 68 70 } //01 00  http://www.31334.info/1stupload.php
		$a_01_1 = {5c 61 70 70 64 61 74 61 2e 6a 70 67 } //01 00  \appdata.jpg
		$a_01_2 = {5c 77 69 6e 2e 73 79 73 } //00 00  \win.sys
	condition:
		any of ($a_*)
 
}