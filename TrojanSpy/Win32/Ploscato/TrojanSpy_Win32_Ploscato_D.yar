
rule TrojanSpy_Win32_Ploscato_D{
	meta:
		description = "TrojanSpy:Win32/Ploscato.D,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {75 73 65 72 33 37 37 30 34 00 } //01 00  獵牥㜳〷4
		$a_01_1 = {64 75 6d 2e 65 78 65 00 6f 75 74 70 75 74 2e 74 78 74 00 } //01 00 
		$a_01_2 = {2f 73 69 6c 65 6e 74 69 6e 73 74 61 6c 6c 00 } //01 00 
		$a_01_3 = {76 69 64 65 6f 64 72 76 } //01 00  videodrv
		$a_01_4 = {74 61 73 6b 6b 69 6c 6c 20 2f 69 6d 20 72 65 67 2e 65 78 65 00 } //01 00 
		$a_01_5 = {64 75 6d 70 20 67 72 61 62 62 65 72 } //00 00  dump grabber
		$a_00_6 = {87 10 00 00 } //97 72 
	condition:
		any of ($a_*)
 
}