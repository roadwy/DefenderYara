
rule Trojan_Win32_ModiLoader_GA_MTB{
	meta:
		description = "Trojan:Win32/ModiLoader.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_81_0 = {72 65 73 70 6f 6e 73 65 74 65 78 74 } //01 00  responsetext
		$a_81_1 = {5b 49 6e 74 65 72 6e 65 74 53 68 6f 72 74 63 75 74 5d } //01 00  [InternetShortcut]
		$a_81_2 = {45 43 48 4f 20 46 7c 78 63 6f 70 79 20 } //01 00  ECHO F|xcopy 
		$a_81_3 = {20 2f 4b 20 2f 44 20 2f 48 20 2f 59 } //01 00   /K /D /H /Y
		$a_81_4 = {43 3a 5c 57 69 6e 64 6f 77 73 20 5c 53 79 73 74 65 6d 33 32 5c 65 61 73 69 6e 76 6f 6b 65 72 2e 65 78 65 } //01 00  C:\Windows \System32\easinvoker.exe
		$a_81_5 = {4b 44 45 43 4f 2e 62 61 74 } //01 00  KDECO.bat
		$a_81_6 = {70 69 6e 67 20 31 32 37 2e 30 2e 30 2e 31 20 2d 6e } //01 00  ping 127.0.0.1 -n
		$a_01_7 = {73 74 61 72 74 20 2f 6d 69 6e 20 70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 2d 69 6e 70 75 74 66 6f 72 6d 61 74 20 6e 6f 6e 65 20 2d 6f 75 74 70 75 74 66 6f 72 6d 61 74 20 6e 6f 6e 65 20 2d 4e 6f 6e 49 6e 74 65 72 61 63 74 69 76 65 20 2d 43 6f 6d 6d 61 6e 64 20 22 41 64 64 2d 4d 70 50 72 65 66 65 72 65 6e 63 65 20 2d 45 78 63 6c 75 73 69 6f 6e 50 61 74 68 20 27 43 3a 5c 55 73 65 72 73 27 22 20 26 20 65 78 69 74 } //00 00  start /min powershell.exe -inputformat none -outputformat none -NonInteractive -Command "Add-MpPreference -ExclusionPath 'C:\Users'" & exit
	condition:
		any of ($a_*)
 
}