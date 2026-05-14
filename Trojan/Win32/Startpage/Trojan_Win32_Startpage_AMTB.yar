
rule Trojan_Win32_Startpage_AMTB{
	meta:
		description = "Trojan:Win32/Startpage!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 08 00 00 "
		
	strings :
		$a_80_0 = {74 61 73 6b 6b 69 6c 6c 2e 65 78 65 20 2f 69 6d 20 4b 53 61 66 65 54 72 61 79 2e 65 78 65 20 2f 66 } //taskkill.exe /im KSafeTray.exe /f  2
		$a_80_1 = {43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 69 65 78 70 6c 6f 72 65 2e 65 78 65 20 68 74 74 70 3a 2f 2f 77 77 77 2e 79 6d 74 75 6b 75 2e 63 6f 6d 2f 78 67 2f 3f 74 61 6e } //C:\Program Files\Internet Explorer\iexplore.exe http://www.ymtuku.com/xg/?tan  4
		$a_80_2 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 73 79 73 74 65 6d 33 32 5c 69 65 2e 62 61 74 } //C:\WINDOWS\system32\ie.bat  1
		$a_80_3 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 73 79 73 74 65 6d 33 32 5c 71 78 2e 62 61 74 } //C:\WINDOWS\system32\qx.bat  1
		$a_80_4 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 73 79 73 74 65 6d 33 32 5c 33 36 30 2e 62 61 74 } //C:\WINDOWS\system32\360.bat  1
		$a_80_5 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 73 79 73 74 65 6d 33 32 5c 74 74 2e 62 61 74 } //C:\WINDOWS\system32\tt.bat  1
		$a_80_6 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 73 79 73 74 65 6d 33 32 5c 61 6f 79 6f 75 2e 62 61 74 } //C:\WINDOWS\system32\aoyou.bat  1
		$a_80_7 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 73 79 73 74 65 6d 33 32 5c 67 6f 6f 67 6c 65 2e 62 61 74 } //C:\WINDOWS\system32\google.bat  1
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*4+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1) >=10
 
}