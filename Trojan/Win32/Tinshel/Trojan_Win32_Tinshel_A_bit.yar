
rule Trojan_Win32_Tinshel_A_bit{
	meta:
		description = "Trojan:Win32/Tinshel.A!bit,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {68 68 a4 00 00 8d 90 01 03 68 0a 00 37 c7 52 e8 90 01 03 ff 68 68 a4 00 00 8d 90 01 03 68 c0 a8 02 1e 50 e8 90 01 03 ff 90 00 } //01 00 
		$a_01_1 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //01 00  SOFTWARE\Microsoft\Windows\CurrentVersion\Run
		$a_01_2 = {3c 73 75 62 73 63 20 72 65 71 75 65 73 74 20 63 6f 64 65 3d 22 31 22 3e 25 75 3c 2f 72 65 71 75 65 73 74 3e } //01 00  <subsc request code="1">%u</request>
		$a_01_3 = {25 64 2e 25 64 2e 25 64 2e 25 64 20 25 73 } //00 00  %d.%d.%d.%d %s
	condition:
		any of ($a_*)
 
}