
rule VirTool_BAT_Injector_EK{
	meta:
		description = "VirTool:BAT/Injector.EK,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {d6 20 ff 00 00 00 5f 91 06 09 91 61 9c 09 17 d6 } //1
		$a_01_1 = {00 41 00 44 49 00 4b 65 79 62 6f 61 72 64 48 6f 6f 6b 00 44 43 49 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule VirTool_BAT_Injector_EK_2{
	meta:
		description = "VirTool:BAT/Injector.EK,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 06 00 00 "
		
	strings :
		$a_00_0 = {49 6e 6a 65 63 74 4e 65 74 00 } //1 湉敪瑣敎t
		$a_00_1 = {49 6e 6a 65 63 74 00 44 6e 45 00 } //1
		$a_00_2 = {70 00 69 00 6e 00 67 00 20 00 2d 00 6e 00 20 00 31 00 20 00 2d 00 77 00 20 00 33 00 30 00 30 00 30 00 20 00 31 00 2e 00 31 00 2e 00 31 00 2e 00 31 00 } //1 ping -n 1 -w 3000 1.1.1.1
		$a_00_3 = {2f 00 43 00 20 00 7b 00 30 00 7d 00 20 00 22 00 7b 00 34 00 7d 00 22 00 20 00 26 00 20 00 7b 00 31 00 7d 00 20 00 26 00 20 00 7b 00 32 00 7d 00 20 00 22 00 7b 00 35 00 7d 00 22 00 20 00 26 00 20 00 7b 00 33 00 7d 00 20 00 22 00 7b 00 35 00 7d 00 22 00 } //1 /C {0} "{4}" & {1} & {2} "{5}" & {3} "{5}"
		$a_00_4 = {2f 00 63 00 20 00 72 00 65 00 67 00 20 00 61 00 64 00 64 00 20 00 22 00 48 00 4b 00 43 00 55 00 5c 00 53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 4e 00 54 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 57 00 69 00 6e 00 6c 00 6f 00 67 00 6f 00 6e 00 22 00 20 00 2f 00 66 00 20 00 2f 00 76 00 20 00 73 00 68 00 65 00 6c 00 6c 00 20 00 2f 00 74 00 20 00 52 00 45 00 47 00 5f 00 53 00 5a 00 20 00 2f 00 64 00 20 00 65 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 2e 00 65 00 78 00 65 00 2c 00 22 00 } //1 /c reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /f /v shell /t REG_SZ /d explorer.exe,"
		$a_01_5 = {13 13 02 11 04 20 f8 00 00 00 58 11 12 1f 28 5a 58 11 13 16 1f 28 28 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_01_5  & 1)*1) >=4
 
}