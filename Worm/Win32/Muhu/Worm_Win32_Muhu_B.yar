
rule Worm_Win32_Muhu_B{
	meta:
		description = "Worm:Win32/Muhu.B,SIGNATURE_TYPE_PEHSTR,05 00 04 00 0c 00 00 01 00 "
		
	strings :
		$a_01_0 = {72 65 70 72 6f 64 75 63 65 3a } //01 00  reproduce:
		$a_01_1 = {46 69 6c 65 43 6f 70 79 64 69 72 2c 43 3a 5c 6e 74 64 65 74 65 63 31 5c 63 68 69 6c 64 2c 25 65 6c 65 6d 65 6e 74 25 3a 5c 2c 31 } //01 00  FileCopydir,C:\ntdetec1\child,%element%:\,1
		$a_01_2 = {52 65 67 77 72 69 74 65 2c 52 45 47 5f 53 5a 2c 48 4b 45 59 5f 4c 4f 43 41 4c 5f 4d 41 43 48 49 4e 45 2c 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 70 6f 6c 69 63 69 65 73 5c 45 78 70 6c 6f 72 65 72 5c 52 75 6e 2c 77 69 6e 6c 6f 67 6f 6e 2c 43 3a 5c 6e 74 64 65 74 65 63 31 5c 72 75 6e 2e 65 78 65 } //01 00  Regwrite,REG_SZ,HKEY_LOCAL_MACHINE,SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer\Run,winlogon,C:\ntdetec1\run.exe
		$a_01_3 = {4c 6f 6f 70 2c 20 52 65 61 64 2c 43 3a 5c 6e 74 64 65 74 65 63 31 5c 64 72 69 76 65 4c 69 73 74 2e 74 78 74 } //02 00  Loop, Read,C:\ntdetec1\driveList.txt
		$a_01_4 = {74 73 6b 63 6c 6f 73 65 3a 0d 0a 49 66 57 69 6e 45 78 69 73 74 2c 57 69 6e 64 6f 77 73 20 54 61 73 6b 20 4d 61 6e 61 67 65 72 0d 0a 20 20 7b 0d 0a 20 20 20 77 69 6e 63 6c 6f 73 65 } //02 00 
		$a_01_5 = {57 69 6e 47 65 74 41 63 74 69 76 65 54 69 74 6c 65 2c 20 65 64 0d 0a 20 69 66 69 6e 73 74 72 69 6e 67 2c 65 64 2c 70 72 6f 63 65 73 73 20 65 78 70 6c 6f 72 65 72 0d 0a 20 20 7b 0d 0a 20 20 20 77 69 6e 63 6c 6f 73 65 20 25 65 64 25 } //01 00 
		$a_01_6 = {73 65 74 74 69 6d 65 72 2c 6e 74 64 65 74 65 63 31 } //02 00  settimer,ntdetec1
		$a_01_7 = {69 66 69 6e 73 74 72 69 6e 67 2c 54 69 74 6c 65 2c 47 6f 6f 67 6c 65 20 73 65 61 72 63 68 20 2d 20 4d 69 63 72 6f 73 6f 66 74 20 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 } //02 00  ifinstring,Title,Google search - Microsoft Internet Explorer
		$a_01_8 = {72 75 6e 2c 68 74 74 70 3a 2f 2f 77 77 77 2e 67 6f 6f 67 6c 65 2e 63 6f 6d 2f 63 75 73 74 6f 6d 3f 68 6c 3d 65 6e 26 63 6c 69 65 6e 74 3d 70 75 62 2d 32 31 34 31 32 32 31 33 39 34 38 30 31 32 34 39 26 63 68 61 6e 6e 65 6c 3d 37 32 31 35 34 34 38 38 37 30 } //01 00  run,http://www.google.com/custom?hl=en&client=pub-2141221394801249&channel=7215448870
		$a_01_9 = {73 65 74 74 69 6d 65 72 2c 74 69 74 6c 65 2c 31 30 30 30 } //02 00  settimer,title,1000
		$a_01_10 = {46 69 6c 65 43 6f 70 79 2c 25 65 6c 65 6d 65 6e 74 25 3a 5c 6e 74 64 65 74 65 63 31 2e 65 78 65 2c 63 3a 5c 6e 74 64 65 74 65 63 31 5c 63 68 69 6c 64 5c 6e 74 64 65 74 65 63 31 2e 65 78 65 2c 31 } //02 00  FileCopy,%element%:\ntdetec1.exe,c:\ntdetec1\child\ntdetec1.exe,1
		$a_01_11 = {46 69 6c 65 73 65 74 61 74 74 72 69 62 2c 2b 53 48 2c 43 3a 5c 6e 74 64 65 74 65 63 31 2c 31 2c 31 } //00 00  Filesetattrib,+SH,C:\ntdetec1,1,1
	condition:
		any of ($a_*)
 
}