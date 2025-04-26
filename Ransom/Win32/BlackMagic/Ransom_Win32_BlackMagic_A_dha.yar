
rule Ransom_Win32_BlackMagic_A_dha{
	meta:
		description = "Ransom:Win32/BlackMagic.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 0b 00 00 "
		
	strings :
		$a_01_0 = {63 3a 5c 75 73 65 72 73 5c 70 75 62 6c 69 63 5c 44 6f 63 75 6d 65 6e 74 73 5c 4d 69 63 72 6f 73 6f 66 74 55 70 64 61 74 65 2e 64 6c 6c 2e 42 6c 61 63 6b 4d 61 67 69 63 } //3 c:\users\public\Documents\MicrosoftUpdate.dll.BlackMagic
		$a_01_1 = {72 65 67 20 61 64 64 20 22 68 6b 65 79 5f 63 75 72 72 65 6e 74 5f 75 73 65 72 5c 63 6f 6e 74 72 6f 6c 20 70 61 6e 65 6c 5c 64 65 73 6b 74 6f 70 22 20 2f 76 20 77 61 6c 6c 70 61 70 65 72 20 2f 74 20 72 65 67 5f 73 7a 20 2f 64 20 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 44 6f 63 75 6d 65 6e 74 73 5c 62 61 63 6b 2e 62 6d 70 20 2f 66 } //2 reg add "hkey_current_user\control panel\desktop" /v wallpaper /t reg_sz /d C:\Users\Public\Documents\back.bmp /f
		$a_01_2 = {64 65 6c 20 2f 46 20 22 63 3a 5c 75 73 65 72 73 5c 70 75 62 6c 69 63 5c 44 6f 63 75 6d 65 6e 74 73 5c 62 61 63 6b 2e 62 6d 70 22 } //2 del /F "c:\users\public\Documents\back.bmp"
		$a_01_3 = {72 65 67 20 61 64 64 20 68 6b 63 75 5c 73 6f 66 74 77 61 72 65 5c 6d 69 63 72 6f 73 6f 66 74 5c 77 69 6e 64 6f 77 73 5c 63 75 72 72 65 6e 74 76 65 72 73 69 6f 6e 5c 70 6f 6c 69 63 69 65 73 5c 73 79 73 74 65 6d 20 2f 76 20 64 69 73 61 62 6c 65 74 61 73 6b 6d 67 72 20 2f 74 20 72 65 67 5f 64 77 6f 72 64 20 2f 64 20 31 20 2f 66 } //2 reg add hkcu\software\microsoft\windows\currentversion\policies\system /v disabletaskmgr /t reg_dword /d 1 /f
		$a_00_4 = {5c 48 61 63 6b 65 64 42 79 42 6c 61 63 6b 4d 61 67 69 63 2e 74 78 74 } //2 \HackedByBlackMagic.txt
		$a_00_5 = {69 70 63 6f 6e 66 69 67 20 3e 20 63 3a 5c 75 73 65 72 73 5c 70 75 62 6c 69 63 5c 44 6f 63 75 6d 65 6e 74 73 5c 69 70 2e 74 78 74 } //2 ipconfig > c:\users\public\Documents\ip.txt
		$a_00_6 = {2f 42 6c 61 63 6b 4d 61 67 69 63 32 35 31 31 } //2 /BlackMagic2511
		$a_03_7 = {62 6c 61 6b 6d 61 67 69 63 (32 35 31 31|37 35 33 33) } //2
		$a_01_8 = {31 39 33 2e 31 38 32 2e 31 34 34 2e 38 35 } //1 193.182.144.85
		$a_01_9 = {35 2e 32 33 30 2e 37 30 2e 34 39 } //1 5.230.70.49
		$a_01_10 = {2f 61 70 69 2f 70 75 62 6c 69 63 2f 61 70 69 2f 74 65 73 74 3f 69 70 3d 26 73 74 61 74 75 73 3d 30 26 63 6e 74 3d 31 30 30 26 74 79 70 65 3d 73 65 72 76 65 72 26 6e 75 6d 3d 31 31 31 31 31 31 37 30 } //1 /api/public/api/test?ip=&status=0&cnt=100&type=server&num=11111170
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_00_4  & 1)*2+(#a_00_5  & 1)*2+(#a_00_6  & 1)*2+(#a_03_7  & 1)*2+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1) >=3
 
}