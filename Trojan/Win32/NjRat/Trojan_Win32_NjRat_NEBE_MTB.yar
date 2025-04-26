
rule Trojan_Win32_NjRat_NEBE_MTB{
	meta:
		description = "Trojan:Win32/NjRat.NEBE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 0b 00 00 "
		
	strings :
		$a_01_0 = {59 75 6d 69 2e 65 78 65 } //3 Yumi.exe
		$a_01_1 = {73 65 74 75 70 65 72 2e 62 61 74 } //3 setuper.bat
		$a_01_2 = {6d 69 6e 2e 76 62 73 } //3 min.vbs
		$a_01_3 = {53 6d 61 72 74 20 49 6e 73 74 61 6c 6c 20 4d 61 6b 65 72 20 76 2e 20 35 2e 30 34 } //2 Smart Install Maker v. 5.04
		$a_01_4 = {43 3a 5c 54 45 4d 50 5c 24 69 6e 73 74 5c 32 2e 20 } //2 C:\TEMP\$inst\2. 
		$a_01_5 = {74 61 68 6f 6d 61 } //2 tahoma
		$a_01_6 = {5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 51 75 69 63 6b 20 4c 61 75 6e 63 68 } //2 \Microsoft\Internet Explorer\Quick Launch
		$a_01_7 = {50 72 6f 67 72 61 6d 57 36 34 33 32 44 69 72 } //2 ProgramW6432Dir
		$a_01_8 = {6d 73 63 74 6c 73 5f 70 72 6f 67 72 65 73 73 33 32 } //2 msctls_progress32
		$a_01_9 = {31 39 39 35 2d 32 30 30 32 20 4a 65 61 6e 2d 6c 6f 75 70 20 47 61 69 6c 6c 79 20 } //2 1995-2002 Jean-loup Gailly 
		$a_01_10 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 47 72 70 43 6f 6e 76 5c 4d 61 70 47 72 6f 75 70 } //2 Software\Microsoft\Windows\CurrentVersion\GrpConv\MapGroup
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3+(#a_01_2  & 1)*3+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2+(#a_01_6  & 1)*2+(#a_01_7  & 1)*2+(#a_01_8  & 1)*2+(#a_01_9  & 1)*2+(#a_01_10  & 1)*2) >=25
 
}