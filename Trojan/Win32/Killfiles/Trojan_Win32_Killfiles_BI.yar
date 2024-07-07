
rule Trojan_Win32_Killfiles_BI{
	meta:
		description = "Trojan:Win32/Killfiles.BI,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 95 6c fe ff ff 8b 02 89 85 bc fe ff ff c7 85 f0 fe ff ff 90 01 02 40 00 c7 85 e8 fe ff ff 08 00 00 00 c7 85 00 ff ff ff 02 00 00 00 c7 85 f8 fe ff ff 02 00 00 00 8d 4d 8c 51 b8 10 00 00 00 90 00 } //1
		$a_01_1 = {c7 45 fc 1d 00 00 00 8d 4d cc 89 8d 00 ff ff ff c7 85 f8 fe ff ff 08 40 00 00 6a 00 8d 95 f8 fe ff ff 52 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Killfiles_BI_2{
	meta:
		description = "Trojan:Win32/Killfiles.BI,SIGNATURE_TYPE_PEHSTR,0b 00 0b 00 0b 00 00 "
		
	strings :
		$a_01_0 = {64 65 6c 20 25 73 79 73 74 65 6d 72 6f 6f 74 25 5c 73 79 73 74 65 6d 33 32 5c 69 6e 69 75 73 65 72 31 2e 65 78 65 } //1 del %systemroot%\system32\iniuser1.exe
		$a_01_1 = {64 65 6c 20 25 73 79 73 74 65 6d 72 6f 6f 74 25 5c 73 79 73 74 65 6d 33 32 5c 66 74 70 2e 65 78 65 } //1 del %systemroot%\system32\ftp.exe
		$a_01_2 = {64 65 6c 20 25 73 79 73 74 65 6d 72 6f 6f 74 25 5c 73 79 73 74 65 6d 33 32 5c 74 66 74 70 2e 65 78 65 } //1 del %systemroot%\system32\tftp.exe
		$a_01_3 = {64 65 6c 20 25 73 79 73 74 65 6d 72 6f 6f 74 25 5c 73 79 73 74 65 6d 33 32 5c 63 73 63 72 69 70 74 2e 65 78 65 } //1 del %systemroot%\system32\cscript.exe
		$a_01_4 = {64 65 6c 20 25 73 79 73 74 65 6d 72 6f 6f 74 25 5c 73 79 73 74 65 6d 33 32 5c 6d 73 63 6f 6e 66 69 67 2e 65 78 65 } //1 del %systemroot%\system32\msconfig.exe
		$a_01_5 = {64 65 6c 20 25 73 79 73 74 65 6d 72 6f 6f 74 25 5c 73 79 73 74 65 6d 33 32 5c 61 74 2e 65 78 65 } //1 del %systemroot%\system32\at.exe
		$a_01_6 = {64 65 6c 20 25 73 79 73 74 65 6d 72 6f 6f 74 25 5c 73 79 73 74 65 6d 33 32 5c 71 75 65 72 79 2e 65 78 65 } //1 del %systemroot%\system32\query.exe
		$a_01_7 = {64 65 6c 20 25 73 79 73 74 65 6d 72 6f 6f 74 25 5c 73 79 73 74 65 6d 33 32 5c 69 6e 69 75 73 65 72 31 73 74 61 74 2e 65 78 65 } //1 del %systemroot%\system32\iniuser1stat.exe
		$a_01_8 = {69 6e 69 75 73 65 72 31 20 75 73 65 72 20 6b 65 76 69 6e 20 2f 64 65 6c } //2 iniuser1 user kevin /del
		$a_01_9 = {69 6e 69 75 73 65 72 31 20 75 73 65 72 20 69 69 73 61 64 6d 69 6e 20 2f 64 65 6c } //2 iniuser1 user iisadmin /del
		$a_01_10 = {4b 69 6c 6c 2e 62 61 74 } //2 Kill.bat
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*2+(#a_01_9  & 1)*2+(#a_01_10  & 1)*2) >=11
 
}