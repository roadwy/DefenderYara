
rule Trojan_Win32_Ibashade_PA_MTB{
	meta:
		description = "Trojan:Win32/Ibashade.PA!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 0a 00 00 01 00 "
		
	strings :
		$a_01_0 = {52 61 72 24 45 58 37 2e 73 72 63 37 37 37 5c } //01 00  Rar$EX7.src777\
		$a_01_1 = {25 73 76 6d 63 69 73 2e 65 78 65 } //01 00  %svmcis.exe
		$a_01_2 = {25 73 76 6d 63 69 73 2e 74 78 74 } //01 00  %svmcis.txt
		$a_01_3 = {70 69 70 65 2e 45 78 63 37 37 37 2e 74 6d 70 } //01 00  pipe.Exc777.tmp
		$a_01_4 = {74 68 65 20 73 68 61 64 65 20 64 6f 65 73 6e 27 74 20 77 61 6e 74 20 79 6f 75 20 64 65 61 74 68 } //01 00  the shade doesn't want you death
		$a_01_5 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 77 69 6e 73 76 68 } //01 00  Software\Microsoft\winsvh
		$a_01_6 = {63 6f 70 79 20 76 72 73 20 74 6f 20 73 74 61 72 74 75 70 } //01 00  copy vrs to startup
		$a_01_7 = {41 44 44 20 48 4b 43 55 5c 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 20 2f 66 20 2f 74 20 52 45 47 5f 53 5a 20 2f 76 20 43 4f 4d 4c 4f 41 44 45 52 20 2f 64 20 22 5c 5c 2e 5c 25 73 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 46 6f 78 69 74 52 65 61 64 65 72 5c 62 69 6e 5c 43 4f 4d 37 2e 45 58 45 22 } //01 00  ADD HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run /f /t REG_SZ /v COMLOADER /d "\\.\%sProgram Files\FoxitReader\bin\COM7.EXE"
		$a_01_8 = {61 63 68 73 76 2e 65 78 65 } //01 00  achsv.exe
		$a_01_9 = {64 61 6e 67 65 72 6f 75 73 2e 6c 6e 6b } //00 00  dangerous.lnk
	condition:
		any of ($a_*)
 
}