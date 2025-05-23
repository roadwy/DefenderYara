
rule PWS_Win32_Lmir_F{
	meta:
		description = "PWS:Win32/Lmir.F,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0d 00 0e 00 00 "
		
	strings :
		$a_00_0 = {2f 6c 69 6e 2e 61 73 70 7c 68 74 74 70 3a 2f 2f } //3 /lin.asp|http://
		$a_00_1 = {66 7a 7a 7e 34 21 21 79 79 79 } //3 fzz~4!!yyy
		$a_02_2 = {83 c4 1c b8 01 00 00 00 8a 94 24 ?? ?? 00 00 8a 8c 04 ?? ?? 00 00 32 ca 88 8c 04 ?? ?? 00 00 40 3d 80 00 00 00 7c e1 } //5
		$a_00_3 = {68 ff 0f 1f 00 ff 15 } //2
		$a_00_4 = {20 2f 25 78 40 00 } //1 ⼠砥@
		$a_00_5 = {2e 65 78 65 20 2f 31 30 30 } //2 .exe /100
		$a_00_6 = {2f 31 30 30 33 40 43 3a 5c } //2 /1003@C:\
		$a_00_7 = {6d 68 73 32 2e 65 78 65 } //1 mhs2.exe
		$a_00_8 = {6d 68 73 2e 65 78 65 } //1 mhs.exe
		$a_00_9 = {53 6f 66 74 57 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 SoftWare\Microsoft\Windows\CurrentVersion\Run
		$a_00_10 = {23 33 32 37 37 30 } //1 #32770
		$a_00_11 = {80 40 00 6a 65 } //1
		$a_00_12 = {6d 73 65 6e 64 } //1 msend
		$a_00_13 = {52 61 76 4d 6f 6e 2e 65 78 65 } //1 RavMon.exe
	condition:
		((#a_00_0  & 1)*3+(#a_00_1  & 1)*3+(#a_02_2  & 1)*5+(#a_00_3  & 1)*2+(#a_00_4  & 1)*1+(#a_00_5  & 1)*2+(#a_00_6  & 1)*2+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1+(#a_00_9  & 1)*1+(#a_00_10  & 1)*1+(#a_00_11  & 1)*1+(#a_00_12  & 1)*1+(#a_00_13  & 1)*1) >=13
 
}