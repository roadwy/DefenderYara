
rule Worm_Win32_Verst_A{
	meta:
		description = "Worm:Win32/Verst.A,SIGNATURE_TYPE_PEHSTR,10 00 10 00 0c 00 00 02 00 "
		
	strings :
		$a_01_0 = {53 59 53 54 45 4d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 43 6f 6e 74 72 6f 6c 5c 53 61 66 65 42 6f 6f 74 } //02 00  SYSTEM\CurrentControlSet\Control\SafeBoot
		$a_01_1 = {49 63 6f 6e 3d 25 73 79 73 74 65 6d 25 5c 73 68 65 6c 6c 33 32 2e 64 6c 6c 2c 34 } //02 00  Icon=%system%\shell32.dll,4
		$a_01_2 = {73 68 65 6c 6c 5c 6f 70 65 6e 5c 43 6f 6d 6d 61 6e 64 3d } //02 00  shell\open\Command=
		$a_01_3 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 53 68 65 6c 6c 20 46 6f 6c 64 65 72 73 5c 43 6f 6d 6d 6f 6e 20 41 70 70 44 61 74 61 } //02 00  SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders\Common AppData
		$a_01_4 = {21 41 44 48 3a 52 43 34 2b 52 53 41 } //02 00  !ADH:RC4+RSA
		$a_01_5 = {53 68 65 6c 6c 48 57 44 65 74 65 63 74 69 6f 6e } //02 00  ShellHWDetection
		$a_01_6 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 4d 53 72 74 6e 5c 76 61 6c 75 65 } //02 00  Software\Microsoft\Windows\CurrentVersion\MSrtn\value
		$a_01_7 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 5c 73 72 74 73 65 72 76 } //01 00  SOFTWARE\Microsoft\Windows\CurrentVersion\Run\srtserv
		$a_01_8 = {68 74 74 70 3a 2f 2f 70 73 79 6e 65 72 67 69 2e 64 6b 2f 64 61 74 61 } //01 00  http://psynergi.dk/data
		$a_01_9 = {68 74 74 70 3a 2f 2f 6b 75 62 75 73 73 65 2e 72 75 2f 64 61 74 61 } //01 00  http://kubusse.ru/data
		$a_01_10 = {68 74 74 70 3a 2f 2f 73 2d 65 6c 69 73 61 2e 72 75 2f 64 61 74 61 } //01 00  http://s-elisa.ru/data
		$a_01_11 = {68 74 74 70 3a 2f 2f 65 64 61 2e 72 75 2f 64 61 74 61 } //00 00  http://eda.ru/data
	condition:
		any of ($a_*)
 
}
rule Worm_Win32_Verst_A_2{
	meta:
		description = "Worm:Win32/Verst.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {c2 ee f1 f1 f2 e0 ed ee e2 eb e5 ed e8 e5 20 e4 ee f1 f2 f3 ef e0 20 ea 20 57 4d 49 44 00 00 00 } //01 00 
		$a_03_1 = {55 8b ec 80 7d 08 01 75 1c 6a 00 a1 90 01 04 50 b8 90 01 04 50 6a 03 e8 90 01 04 a3 90 01 04 eb 12 a1 90 01 04 50 e8 90 01 04 33 c0 a3 90 01 04 5d c2 04 00 90 00 } //01 00 
		$a_00_2 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 4d 53 72 74 6e 5c 70 } //01 00  Software\Microsoft\Windows\CurrentVersion\MSrtn\p
		$a_00_3 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //00 00  SOFTWARE\Borland\Delphi\RTL
	condition:
		any of ($a_*)
 
}