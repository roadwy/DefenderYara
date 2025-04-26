
rule Trojan_Win32_Satacom_MSR{
	meta:
		description = "Trojan:Win32/Satacom!MSR,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 05 00 00 "
		
	strings :
		$a_01_0 = {63 6d 64 2e 65 78 65 20 2f 63 20 73 74 61 72 74 20 2f 42 20 70 6f 77 65 72 73 68 65 6c 6c 20 2d 77 69 6e 64 6f 77 73 74 79 6c 65 20 68 69 64 64 65 6e 20 2d 63 6f 6d 6d 61 6e 64 } //1 cmd.exe /c start /B powershell -windowstyle hidden -command
		$a_01_1 = {2f 2f 34 33 35 34 36 34 2e 63 6f 6d 2f } //5 //435464.com/
		$a_01_2 = {53 6f 66 74 77 61 72 65 5c 66 75 63 6b 79 6f 75 5c } //5 Software\fuckyou\
		$a_01_3 = {63 6d 64 20 2f 43 20 72 65 67 73 76 72 33 32 20 2f 73 20 22 25 73 22 } //1 cmd /C regsvr32 /s "%s"
		$a_01_4 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //1 URLDownloadToFileA
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=13
 
}