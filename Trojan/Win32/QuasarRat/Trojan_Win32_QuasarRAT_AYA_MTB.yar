
rule Trojan_Win32_QuasarRAT_AYA_MTB{
	meta:
		description = "Trojan:Win32/QuasarRAT.AYA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_01_0 = {31 34 31 2e 39 38 2e 37 2e 35 31 2f 73 74 75 62 2f 53 68 65 6c 6c 2e 65 78 65 } //2 141.98.7.51/stub/Shell.exe
		$a_01_1 = {58 57 4f 52 4d 20 4e 4f 54 20 46 49 58 45 44 } //1 XWORM NOT FIXED
		$a_01_2 = {70 6f 77 65 72 73 68 65 6c 6c 20 2d 69 6e 70 75 74 66 6f 72 6d 61 74 20 6e 6f 6e 65 20 2d 6f 75 74 70 75 74 66 6f 72 6d 61 74 20 6e 6f 6e 65 20 2d 4e 6f 6e 49 6e 74 65 72 61 63 74 69 76 65 20 2d 43 6f 6d 6d 61 6e 64 } //1 powershell -inputformat none -outputformat none -NonInteractive -Command
		$a_01_3 = {41 64 64 2d 4d 70 50 72 65 66 65 72 65 6e 63 65 20 2d 45 78 63 6c 75 73 69 6f 6e 50 61 74 68 20 43 3a 5c 57 69 6e 64 6f 77 73 5c 50 6f 77 65 72 53 68 65 6c 6c } //1 Add-MpPreference -ExclusionPath C:\Windows\PowerShell
		$a_01_4 = {49 6e 6a 65 63 74 69 6f 6e 20 63 6f 6d 70 6c 65 74 65 64 21 } //1 Injection completed!
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=6
 
}