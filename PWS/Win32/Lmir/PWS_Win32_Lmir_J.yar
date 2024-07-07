
rule PWS_Win32_Lmir_J{
	meta:
		description = "PWS:Win32/Lmir.J,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 0b 00 00 "
		
	strings :
		$a_00_0 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //1 SOFTWARE\Borland\Delphi\RTL
		$a_00_1 = {4b 52 65 67 45 78 2e 65 78 65 } //1 KRegEx.exe
		$a_00_2 = {4b 56 58 50 2e 6b 78 70 } //1 KVXP.kxp
		$a_00_3 = {33 36 30 74 72 61 79 2e 65 78 65 } //1 360tray.exe
		$a_00_4 = {77 69 6e 2e 69 6e 69 } //1 win.ini
		$a_00_5 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 53 68 65 6c 6c 20 46 6f 6c 64 65 72 73 } //1 SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders
		$a_00_6 = {2e 6c 6e 6b } //1 .lnk
		$a_00_7 = {43 3a 5c 57 69 6e 64 6f 77 73 5c 69 65 78 70 6c 6f 72 65 2e 24 } //1 C:\Windows\iexplore.$
		$a_00_8 = {49 45 66 72 61 6d 65 } //1 IEframe
		$a_00_9 = {3c 61 20 68 72 65 66 3d } //1 <a href=
		$a_02_10 = {6a 00 6a 00 68 90 01 03 00 6a 00 6a 00 e8 90 01 02 fd ff 33 c0 55 68 90 01 03 00 64 ff 30 64 89 20 33 c0 5a 59 59 64 89 10 eb 0a 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1+(#a_00_9  & 1)*1+(#a_02_10  & 1)*1) >=11
 
}