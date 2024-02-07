
rule Trojan_Win32_Shipup_B{
	meta:
		description = "Trojan:Win32/Shipup.B,SIGNATURE_TYPE_PEHSTR_EXT,11 00 10 00 06 00 00 0a 00 "
		
	strings :
		$a_00_0 = {8b 44 24 04 8a 08 84 c9 74 08 80 c1 03 88 08 40 eb f2 c3 8b 44 24 04 8a 08 84 c9 74 07 fe c1 88 08 40 eb f3 c3 } //05 00 
		$a_01_1 = {4d 69 63 72 6f 73 6f 66 74 46 6c 61 73 68 } //01 00  MicrosoftFlash
		$a_00_2 = {5c 6c 64 2e 65 78 65 } //01 00  \ld.exe
		$a_00_3 = {5c 66 69 6c 65 74 69 6d 65 2e 64 61 74 } //01 00  \filetime.dat
		$a_00_4 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 53 68 69 70 54 72 } //01 00  Software\Microsoft\ShipTr
		$a_00_5 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //00 00  Software\Microsoft\Windows\CurrentVersion\Run
	condition:
		any of ($a_*)
 
}