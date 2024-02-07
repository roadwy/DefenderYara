
rule TrojanSpy_Win32_Alinaos_G{
	meta:
		description = "TrojanSpy:Win32/Alinaos.G,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 05 00 00 03 00 "
		
	strings :
		$a_03_0 = {75 70 64 61 74 65 69 6e 74 65 72 76 61 6c 3d 90 02 08 63 61 72 64 69 6e 74 65 72 76 61 6c 3d 90 00 } //03 00 
		$a_03_1 = {6c 6f 67 3d 31 90 02 08 7b 5b 21 31 37 21 5d 7d 7b 5b 21 31 38 21 5d 7d 90 02 08 6c 6f 67 3d 30 90 02 08 7b 5b 21 31 37 21 5d 7d 7b 5b 21 31 39 21 5d 7d 90 00 } //01 00 
		$a_00_2 = {25 73 6e 74 66 73 2e 64 61 74 } //01 00  %sntfs.dat
		$a_01_3 = {68 74 74 70 3a 2f 2f 25 73 3a 25 64 7b 5b 21 34 21 5d } //01 00  http://%s:%d{[!4!]
		$a_00_4 = {77 69 6e 2d 66 69 72 65 77 61 6c 6c 2e 65 78 65 } //00 00  win-firewall.exe
		$a_00_5 = {87 10 } //00 00 
	condition:
		any of ($a_*)
 
}