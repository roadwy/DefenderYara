
rule Worm_Win32_Autorun_RZ{
	meta:
		description = "Worm:Win32/Autorun.RZ,SIGNATURE_TYPE_PEHSTR,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {74 65 73 74 63 61 74 61 6c 6f 67 65 2e 62 79 2e 72 75 2f } //01 00  testcataloge.by.ru/
		$a_01_1 = {73 68 65 6c 6c 5c 6f 70 65 6e 5c 43 6f 6d 6d 61 6e 64 3d 7a 65 74 75 70 2e 65 78 65 } //01 00  shell\open\Command=zetup.exe
		$a_01_2 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 4f 6e 63 65 } //01 00  SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
		$a_01_3 = {52 43 50 54 20 54 4f 3a 20 3c } //01 00  RCPT TO: <
		$a_01_4 = {53 45 4c 45 43 54 20 2a 20 46 52 4f 4d 20 57 69 6e 33 32 5f 42 49 4f 53 2c 53 65 72 69 61 6c 4e 75 6d 62 65 72 } //01 00  SELECT * FROM Win32_BIOS,SerialNumber
		$a_01_5 = {66 61 73 6d 2e 65 78 65 } //00 00  fasm.exe
	condition:
		any of ($a_*)
 
}