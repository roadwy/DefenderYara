
rule Trojan_Win32_Cromptui_B{
	meta:
		description = "Trojan:Win32/Cromptui.B,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_01_0 = {48 54 54 50 57 2d 47 4e 49 4b } //1 HTTPW-GNIK
		$a_01_1 = {54 45 4d 50 5c 5c 61 64 6f 62 65 75 70 64 2e 65 78 65 } //1 TEMP\\adobeupd.exe
		$a_01_2 = {5c 41 64 6f 62 65 20 43 65 6e 74 65 72 2e 6c 6e 6b } //1 \Adobe Center.lnk
		$a_01_3 = {5c 6e 65 74 62 6e 2e 65 78 65 } //1 \netbn.exe
		$a_01_4 = {5c 6e 65 74 64 63 2e 65 78 65 } //1 \netdc.exe
		$a_01_5 = {2f 63 67 69 2d 62 69 6e 2f 43 4d 53 5f 43 6c 65 61 72 41 6c 6c 2e 63 67 69 } //1 /cgi-bin/CMS_ClearAll.cgi
		$a_01_6 = {2f 63 67 69 2d 62 69 6e 2f 43 4d 53 5f 4c 69 73 74 49 6d 67 2e 63 67 69 } //1 /cgi-bin/CMS_ListImg.cgi
		$a_01_7 = {2f 63 67 69 2d 62 69 6e 2f 43 4d 53 5f 53 75 62 69 74 41 6c 6c 2e 63 67 69 } //1 /cgi-bin/CMS_SubitAll.cgi
		$a_01_8 = {52 4d 54 43 55 52 52 } //1 RMTCURR
		$a_01_9 = {69 66 20 65 78 69 73 74 20 22 43 3a 5c 54 45 4d 50 5c 5c 61 64 6f 62 65 75 70 64 2e 65 78 65 22 20 64 65 6c 20 2f 71 20 22 43 3a 5c 54 45 4d 50 5c 5c 61 64 6f 62 65 75 70 64 2e 65 78 65 22 } //1 if exist "C:\TEMP\\adobeupd.exe" del /q "C:\TEMP\\adobeupd.exe"
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=10
 
}