
rule Trojan_Win32_Agent_PA_MTB{
	meta:
		description = "Trojan:Win32/Agent.PA!MTB,SIGNATURE_TYPE_PEHSTR,0e 00 0e 00 0f 00 00 01 00 "
		
	strings :
		$a_01_0 = {64 6c 73 68 73 76 63 2e 65 78 65 } //01 00  dlshsvc.exe
		$a_01_1 = {66 74 73 68 6f 73 74 2e 65 78 65 } //01 00  ftshost.exe
		$a_01_2 = {6d 73 68 6f 73 74 2e 65 78 65 } //01 00  mshost.exe
		$a_01_3 = {6d 73 74 72 61 79 2e 65 78 65 } //01 00  mstray.exe
		$a_01_4 = {5c 5c 2e 5c 6d 61 69 6c 73 6c 6f 74 5c 66 32 38 37 34 33 32 34 33 32 30 38 37 38 } //01 00  \\.\mailslot\f2874324320878
		$a_01_5 = {61 64 64 20 48 4b 43 55 5c 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 41 64 76 61 6e 63 65 64 20 2f 76 20 48 69 64 64 65 6e 20 2f 74 20 52 45 47 5f 44 57 4f 52 44 20 2f 64 20 30 78 30 30 30 30 30 30 30 30 20 2f 66 } //01 00  add HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced /v Hidden /t REG_DWORD /d 0x00000000 /f
		$a_01_6 = {61 64 64 20 25 73 5c 25 73 20 2f 76 20 25 73 20 2f 74 20 52 45 47 5f 53 5a 20 2f 64 20 22 25 73 22 20 2f 66 } //01 00  add %s\%s /v %s /t REG_SZ /d "%s" /f
		$a_01_7 = {66 74 73 72 69 2e 70 68 70 3f 67 65 74 26 65 78 65 } //01 00  ftsri.php?get&exe
		$a_01_8 = {66 73 69 2e 70 68 70 3f 67 65 74 26 65 78 65 } //01 00  fsi.php?get&exe
		$a_01_9 = {6d 71 6b 6c 64 72 76 } //01 00  mqkldrv
		$a_01_10 = {70 73 61 78 6c 73 6c } //01 00  psaxlsl
		$a_01_11 = {61 6c 6c 6e 65 77 73 6d 65 64 69 61 2e 77 65 62 61 74 75 2e 63 6f 6d } //01 00  allnewsmedia.webatu.com
		$a_01_12 = {6c 6f 76 65 63 61 74 61 6c 6f 67 2e 63 6f 6d 6c 75 2e 63 6f 6d } //01 00  lovecatalog.comlu.com
		$a_01_13 = {79 6f 75 72 73 73 61 67 72 65 67 61 74 6f 72 2e 63 6f 6d 6c 75 2e 63 6f 6d } //01 00  yourssagregator.comlu.com
		$a_01_14 = {31 d2 3b 5d 14 0f 9c c2 f7 da 21 da 8b 5d 10 0f b6 04 1a 8d 5a 01 f6 d8 30 04 31 41 39 f9 7c e0 } //00 00 
	condition:
		any of ($a_*)
 
}