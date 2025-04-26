
rule Trojan_Win32_BatchWiper_MA_MTB{
	meta:
		description = "Trojan:Win32/BatchWiper.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 05 00 00 "
		
	strings :
		$a_03_0 = {8b 55 f8 81 c2 00 40 00 00 89 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 83 c0 05 50 8b 0d ?? ?? ?? ?? 51 6a 01 8b 15 ?? ?? ?? ?? 52 ff 15 ?? ?? ?? ?? a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 03 45 0c 89 45 fc 8b 4d 0c 03 4d 08 89 0d b0 b3 40 00 8b 45 fc 8b e5 5d c2 } //5
		$a_01_1 = {2e 74 6d 70 5c 44 72 65 53 5f 58 2e 62 61 74 } //5 .tmp\DreS_X.bat
		$a_01_2 = {74 61 73 6b 6b 69 6c 6c 20 2f 66 20 2f 69 6d 20 74 61 73 6b 6d 67 72 2e 65 78 65 } //1 taskkill /f /im taskmgr.exe
		$a_01_3 = {50 6c 65 61 73 65 20 65 6e 74 65 72 20 74 68 65 20 70 61 73 73 77 6f 72 64 2e } //1 Please enter the password.
		$a_01_4 = {40 65 63 68 6f 20 6f 66 66 } //1 @echo off
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=13
 
}