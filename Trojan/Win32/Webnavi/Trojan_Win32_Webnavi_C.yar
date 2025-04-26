
rule Trojan_Win32_Webnavi_C{
	meta:
		description = "Trojan:Win32/Webnavi.C,SIGNATURE_TYPE_PEHSTR,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {5c 50 6f 6c 69 63 69 65 73 5c 45 78 70 6c 6f 72 65 72 20 2f 76 20 4e 6f 49 6e 74 65 72 6e 65 74 49 63 6f 6e 20 2f 74 20 52 45 47 5f 44 57 4f 52 44 20 2f 64 20 30 30 30 30 30 30 30 31 20 2f 66 } //1 \Policies\Explorer /v NoInternetIcon /t REG_DWORD /d 00000001 /f
		$a_01_1 = {63 6f 70 79 20 2f 59 20 22 25 6d 79 66 69 6c 65 73 25 5c 6c 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 2e 6c 6e 6b 22 20 22 43 3a 5c 44 6f 63 75 6d 65 6e 74 73 20 61 6e 64 20 53 65 74 74 69 6e 67 73 5c 41 6c 6c 20 55 73 65 72 73 5c } //1 copy /Y "%myfiles%\lnternet Explorer.lnk" "C:\Documents and Settings\All Users\
		$a_01_2 = {2f 00 2f 00 77 00 77 00 77 00 2e 00 37 00 38 00 39 00 64 00 68 00 2e 00 63 00 6f 00 6d 00 } //1 //www.789dh.com
		$a_01_3 = {65 63 68 6f 20 79 7c 63 61 63 6c 73 2e 65 78 65 20 63 3a 5c 64 6f 63 75 6d 65 7e 31 5c 61 6c 6c 75 73 65 7e 31 5c } //1 echo y|cacls.exe c:\docume~1\alluse~1\
		$a_01_4 = {71 75 69 63 6b 6c 7e 31 5c 6c 6e 74 65 72 6e 7e 31 2e 6c 6e 6b 20 2f 70 20 65 76 65 72 79 6f 6e 65 3a 72 20 3e 6e 75 6c 20 31 3e 6e 75 6c } //1 quickl~1\lntern~1.lnk /p everyone:r >nul 1>nul
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}