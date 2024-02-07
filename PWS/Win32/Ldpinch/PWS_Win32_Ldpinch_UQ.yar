
rule PWS_Win32_Ldpinch_UQ{
	meta:
		description = "PWS:Win32/Ldpinch.UQ,SIGNATURE_TYPE_PEHSTR_EXT,ffffffa4 01 ffffffa1 01 18 00 00 64 00 "
		
	strings :
		$a_02_0 = {33 c0 eb 1a 80 3d 90 01 02 40 00 32 74 0c 81 3d 90 01 02 40 00 33 35 34 20 75 e7 40 47 c6 07 00 90 00 } //64 00 
		$a_00_1 = {58 69 6e 63 68 55 73 65 72 } //64 00  XinchUser
		$a_00_2 = {45 48 4c 4f 20 6c 6f 63 61 6c 68 6f 73 74 } //64 00  EHLO localhost
		$a_00_3 = {32 32 30 20 46 54 50 } //01 00  220 FTP
		$a_00_4 = {69 6d 61 67 65 2f 6a 70 65 67 } //01 00  image/jpeg
		$a_00_5 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 53 68 65 6c 6c 4e 6f 52 6f 61 6d 5c 4d 55 49 43 61 63 68 65 } //01 00  SOFTWARE\Microsoft\Windows\ShellNoRoam\MUICache
		$a_00_6 = {70 29 52 23 6b 65 72 6e 65 6c 33 32 2e 64 6c 6c } //01 00  p)R#kernel32.dll
		$a_00_7 = {42 75 69 6c 64 65 72 2e 65 78 65 } //01 00  Builder.exe
		$a_00_8 = {68 74 74 70 3a 2f 2f 73 74 61 73 6d 61 73 74 65 72 2e 68 75 74 32 2e 72 75 2f 72 63 76 2e 70 68 70 } //01 00  http://stasmaster.hut2.ru/rcv.php
		$a_00_9 = {23 63 68 61 6e 6e 65 6c } //01 00  #channel
		$a_00_10 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 73 63 72 65 65 6e 2e 6c 6f 67 } //01 00  C:\WINDOWS\screen.log
		$a_00_11 = {78 69 6e 63 68 70 61 73 73 } //01 00  xinchpass
		$a_00_12 = {5c 74 65 6d 70 2e 6a 70 67 } //01 00  \temp.jpg
		$a_00_13 = {53 75 62 6a 65 63 74 3a 20 48 65 6c 6c 6f 20 66 72 6f 6d 20 25 73 } //01 00  Subject: Hello from %s
		$a_00_14 = {43 6f 6e 74 65 6e 74 2d 54 79 70 65 3a 20 61 70 70 6c 69 63 61 74 69 6f 6e 2f 6f 63 74 65 74 2d 73 74 72 65 61 6d 3b 20 6e 61 6d 65 3d 72 65 70 6f 72 74 2e 62 69 6e } //01 00  Content-Type: application/octet-stream; name=report.bin
		$a_00_15 = {43 6f 6e 74 65 6e 74 2d 44 69 73 70 6f 73 69 74 69 6f 6e 3a 20 61 74 74 61 63 68 6d 65 6e 74 3b 20 66 69 6c 65 6e 61 6d 65 3d 72 65 70 6f 72 74 2e 62 69 6e } //01 00  Content-Disposition: attachment; filename=report.bin
		$a_00_16 = {52 43 50 54 20 54 4f 3a 20 76 69 63 74 6f 72 40 72 75 73 61 6c 2e 72 75 } //01 00  RCPT TO: victor@rusal.ru
		$a_00_17 = {5c 73 76 63 68 6f 73 74 2e 64 6c 6c } //01 00  \svchost.dll
		$a_00_18 = {5c 73 76 63 68 6f 73 74 2e 65 78 65 } //01 00  \svchost.exe
		$a_00_19 = {5c 47 65 6e 65 72 69 63 20 48 6f 73 74 20 50 72 6f 63 65 73 73 20 66 6f 72 20 57 69 6e 33 32 20 53 65 72 76 69 63 65 73 } //01 00  \Generic Host Process for Win32 Services
		$a_00_20 = {68 74 74 70 3a 2f 2f 6c 6f 63 61 6c 68 6f 73 74 2f 73 74 2e 70 68 70 } //01 00  http://localhost/st.php
		$a_00_21 = {53 65 61 72 63 68 20 50 61 67 65 } //01 00  Search Page
		$a_00_22 = {68 74 74 70 3a 2f 2f 79 61 6e 64 65 78 2e 72 75 } //01 00  http://yandex.ru
		$a_00_23 = {43 3a 5c 6b 68 6b 68 6e 6b 75 68 } //00 00  C:\khkhnkuh
	condition:
		any of ($a_*)
 
}