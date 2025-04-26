
rule Trojan_Win32_Shutdown_T{
	meta:
		description = "Trojan:Win32/Shutdown.T,SIGNATURE_TYPE_PEHSTR,06 00 06 00 07 00 00 "
		
	strings :
		$a_01_0 = {63 6f 70 79 20 76 69 72 75 73 2e 62 61 74 20 43 3a 5c 77 69 6e 64 6f 77 73 5c } //2 copy virus.bat C:\windows\
		$a_01_1 = {6e 65 74 20 75 73 65 72 20 72 6f 63 31 33 } //2 net user roc13
		$a_01_2 = {6d 6b 64 69 72 20 25 75 73 65 72 70 72 6f 66 69 6c 65 25 5c 64 65 73 6b 74 6f 70 5c 76 69 72 75 73 33 30 30 30 } //2 mkdir %userprofile%\desktop\virus3000
		$a_01_3 = {73 68 75 74 64 6f 77 6e 20 2d 72 54 68 65 20 62 65 73 74 20 68 61 6d 62 75 72 67 65 72 20 69 6d 61 67 65 2e 70 6e 67 2e 62 61 74 } //2 shutdown -rThe best hamburger image.png.bat
		$a_01_4 = {65 63 68 6f 20 41 20 56 49 52 55 53 20 48 41 53 20 42 45 45 4e 20 44 45 54 45 43 54 45 44 20 4f 4e 20 59 4f 55 52 20 43 4f 4d 50 55 54 45 52 20 41 4e 44 20 57 49 4c 4c 20 45 52 41 53 45 20 45 56 45 52 59 54 48 49 4e 47 21 } //2 echo A VIRUS HAS BEEN DETECTED ON YOUR COMPUTER AND WILL ERASE EVERYTHING!
		$a_01_5 = {73 74 61 72 74 20 69 65 78 70 6c 6f 72 65 2e 65 78 65 20 77 77 77 2e } //1 start iexplore.exe www.
		$a_01_6 = {72 65 67 20 61 64 64 20 48 4b 45 59 5f } //1 reg add HKEY_
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=6
 
}