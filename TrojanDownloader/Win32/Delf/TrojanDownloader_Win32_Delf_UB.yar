
rule TrojanDownloader_Win32_Delf_UB{
	meta:
		description = "TrojanDownloader:Win32/Delf.UB,SIGNATURE_TYPE_PEHSTR,0d 00 0d 00 0d 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c } //01 00  SOFTWARE\Borland\Delphi\
		$a_01_1 = {46 61 73 74 4d 4d 20 42 6f 72 6c 61 6e 64 20 45 64 69 74 69 6f 6e } //01 00  FastMM Borland Edition
		$a_01_2 = {74 6d 70 64 6f 77 6e 33 32 2e 64 6c 6c } //01 00  tmpdown32.dll
		$a_01_3 = {68 74 74 70 3a 2f 2f 77 77 77 2e } //01 00  http://www.
		$a_01_4 = {2f 70 64 66 2e 70 64 66 } //01 00  /pdf.pdf
		$a_01_5 = {4d 6f 7a 69 6c 6c 61 2f 35 2e 30 20 28 57 69 6e 64 6f 77 73 3b 20 55 3b 20 57 69 6e 64 6f 77 73 20 4e 54 20 35 2e 31 3b 20 65 6e 3b 29 20 47 65 63 6b 6f 2f 33 30 30 36 30 33 30 39 20 46 69 72 65 66 6f 78 2f 31 2e 35 2e 30 2e 37 } //01 00  Mozilla/5.0 (Windows; U; Windows NT 5.1; en;) Gecko/30060309 Firefox/1.5.0.7
		$a_01_6 = {65 64 30 33 35 30 43 45 33 34 39 34 45 42 44 34 35 42 32 41 45 38 41 } //01 00  ed0350CE3494EBD45B2AE8A
		$a_01_7 = {53 79 73 74 65 6d 52 6f 6f 74 } //01 00  SystemRoot
		$a_01_8 = {73 76 63 68 6f 73 74 2e 65 78 65 } //01 00  svchost.exe
		$a_01_9 = {24 28 2c 30 34 38 3c 40 44 48 4c 4c 50 50 54 54 58 58 5c 5c 60 60 64 64 68 68 6c 6c 70 70 74 74 74 74 78 78 78 78 7c 7c 7c 7c } //01 00  $(,048<@DHLLPPTTXX\\``ddhhllppttttxxxx||||
		$a_01_10 = {43 72 65 61 74 65 4d 75 74 65 78 41 } //01 00  CreateMutexA
		$a_01_11 = {57 69 6e 45 78 65 63 } //01 00  WinExec
		$a_01_12 = {45 6e 75 6d 43 61 6c 65 6e 64 61 72 49 6e 66 6f 41 } //00 00  EnumCalendarInfoA
	condition:
		any of ($a_*)
 
}