
rule Backdoor_Win32_Hupigon_ZP{
	meta:
		description = "Backdoor:Win32/Hupigon.ZP,SIGNATURE_TYPE_PEHSTR,3c 00 3c 00 0b 00 00 32 00 "
		
	strings :
		$a_01_0 = {8b 45 fc 8a 44 18 ff 24 0f 8b 55 f0 8a 54 32 ff 80 e2 0f 32 c2 } //01 00 
		$a_01_1 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 53 65 74 75 70 } //01 00  SOFTWARE\Microsoft\Windows\CurrentVersion\Setup
		$a_01_2 = {22 75 6e 20 75 73 65 72 69 6e 69 74 2e 65 78 65 } //01 00  "un userinit.exe
		$a_01_3 = {6e 65 74 73 65 72 76 69 63 65 2e 65 78 65 } //01 00  netservice.exe
		$a_01_4 = {73 79 73 6e 73 2e 64 6c 6c } //01 00  sysns.dll
		$a_01_5 = {73 76 63 68 6f 73 74 2e 65 78 65 20 2d 6b } //01 00  svchost.exe -k
		$a_01_6 = {70 6c 75 67 69 6e 5c 30 30 31 2e 64 6c 6c } //01 00  plugin\001.dll
		$a_01_7 = {63 6d 64 20 2f 63 20 61 74 20 32 33 3a 35 39 20 73 68 75 74 64 6f 77 6e 20 2d 72 20 2d 74 20 30 } //01 00  cmd /c at 23:59 shutdown -r -t 0
		$a_01_8 = {6b 76 6d 6f 6e 78 70 2e 6b 78 70 } //01 00  kvmonxp.kxp
		$a_01_9 = {63 3a 5c 31 2e 68 69 76 } //01 00  c:\1.hiv
		$a_01_10 = {53 6f 66 74 77 61 72 65 5c 6e 73 } //00 00  Software\ns
	condition:
		any of ($a_*)
 
}