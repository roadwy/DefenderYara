
rule Worm_Win32_Dock_A{
	meta:
		description = "Worm:Win32/Dock.A,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 08 00 00 02 00 "
		
	strings :
		$a_01_0 = {eb 66 8b 5d f8 50 53 e8 88 fe ff ff 85 c0 59 59 be 00 30 00 00 74 13 6a 40 } //02 00 
		$a_03_1 = {6a 10 8d 45 ec 50 56 ff 15 90 01 04 56 ff 15 90 01 04 33 c0 81 7d f8 15 2d 01 00 90 00 } //02 00 
		$a_01_2 = {8d 48 10 56 c7 45 70 15 2d 01 00 c7 45 68 01 00 00 00 89 45 64 89 4d 6c } //01 00 
		$a_01_3 = {25 73 70 61 67 65 66 69 6c 65 73 2e 64 61 74 } //01 00  %spagefiles.dat
		$a_01_4 = {25 73 74 65 6d 70 2e 74 6d 70 } //01 00  %stemp.tmp
		$a_01_5 = {25 73 5c 6d 73 73 65 74 75 70 2e 65 78 65 } //01 00  %s\mssetup.exe
		$a_01_6 = {25 73 5c 77 73 32 68 65 6c 70 2e 64 6c 6c } //01 00  %s\ws2help.dll
		$a_01_7 = {25 73 5c 7e 24 25 73 } //00 00  %s\~$%s
	condition:
		any of ($a_*)
 
}