
rule Backdoor_Win32_Trochil_D_dll{
	meta:
		description = "Backdoor:Win32/Trochil.D.dll!dha,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 15 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 72 75 6e 61 73 2e 65 78 65 } //01 00  \Microsoft\Internet Explorer\runas.exe
		$a_01_1 = {5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 6d 6f 6e } //01 00  \Microsoft\Internet Explorer\mon
		$a_01_2 = {5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 6e 6f 74 65 70 61 64 2e 65 78 65 } //01 00  \Microsoft\Internet Explorer\notepad.exe
		$a_01_3 = {5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 6e 76 73 76 63 2e 65 78 65 } //01 00  \Microsoft\Internet Explorer\nvsvc.exe
		$a_01_4 = {5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 53 42 69 65 44 6c 6c 2e 64 6c 6c } //01 00  \Microsoft\Internet Explorer\SBieDll.dll
		$a_01_5 = {5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 6d 61 69 6e 64 6c 6c 2e 64 6c 6c } //01 00  \Microsoft\Internet Explorer\maindll.dll
		$a_01_6 = {5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 63 6f 6e 68 6f 73 74 2e 65 78 65 } //01 00  \Microsoft\Internet Explorer\conhost.exe
		$a_01_7 = {25 73 5b 25 64 2d 25 64 2d 25 64 20 25 64 3a 25 64 3a 25 64 5d } //01 00  %s[%d-%d-%d %d:%d:%d]
		$a_01_8 = {25 73 5c 25 64 2d 25 30 32 64 2d 25 30 32 64 2e 73 79 73 } //01 00  %s\%d-%02d-%02d.sys
		$a_01_9 = {4b 42 39 32 33 35 36 31 } //01 00  KB923561
		$a_01_10 = {73 72 76 6c 69 63 2e 64 6c 6c } //01 00  srvlic.dll
		$a_01_11 = {75 70 64 61 74 65 2e 6c 6e 6b } //02 00  update.lnk
		$a_01_12 = {64 6c 6c 32 2e 78 6f 72 } //01 00  dll2.xor
		$a_01_13 = {6d 6f 76 65 20 22 25 73 22 20 22 25 73 25 73 22 } //01 00  move "%s" "%s%s"
		$a_01_14 = {63 6f 70 79 20 22 25 73 25 73 22 20 22 25 73 25 73 5c 25 73 22 } //01 00  copy "%s%s" "%s%s\%s"
		$a_01_15 = {6d 6f 76 65 20 22 25 73 25 73 22 20 22 25 73 25 73 22 } //01 00  move "%s%s" "%s%s"
		$a_01_16 = {00 75 70 2e 64 61 74 00 } //02 00 
		$a_01_17 = {00 74 68 69 73 20 69 73 20 55 50 30 30 37 00 } //02 00 
		$a_01_18 = {00 61 64 6d 69 6e 7c 7c 30 39 30 32 00 } //01 00 
		$a_01_19 = {00 4d 65 73 73 61 67 65 4c 6f 6f 70 00 } //01 00 
		$a_01_20 = {00 49 4e 53 00 44 45 4c 00 48 4f 4d 45 00 } //00 00  䤀华䐀䱅䠀䵏E
	condition:
		any of ($a_*)
 
}