
rule TrojanSpy_Win32_Sockawin_A{
	meta:
		description = "TrojanSpy:Win32/Sockawin.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {57 69 6e 73 6f 63 6b 4d 55 54 45 58 31 30 32 } //2 WinsockMUTEX102
		$a_01_1 = {50 61 63 6b 65 64 43 61 74 61 6c 6f 67 49 74 65 6d 00 00 00 25 75 00 00 53 59 53 54 45 4d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 53 65 72 76 69 63 65 73 5c 57 69 6e 53 6f 63 6b 32 5c 57 69 6e 73 6f 63 6b 5f 53 70 69 00 00 ff ff } //2
		$a_01_2 = {68 6f 6d 65 2e 61 73 70 3f 61 63 74 3d 61 31 31 31 31 31 31 31 31 26 66 73 3d 25 64 26 66 70 3d 25 73 26 66 6e 3d 25 73 } //1 home.asp?act=a11111111&fs=%d&fp=%s&fn=%s
		$a_01_3 = {25 73 2f 68 6f 6d 65 2e 61 73 70 3f 74 79 70 65 3d 77 65 62 26 61 63 74 3d 63 33 33 33 33 33 33 33 33 26 66 70 3d 25 73 26 66 6e 3d 25 73 } //1 %s/home.asp?type=web&act=c33333333&fp=%s&fn=%s
		$a_01_4 = {6d 73 77 73 6f 63 6b 2e 64 6c 6c 90 5c 44 6f 77 6e 6c 6f 61 64 65 64 20 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 8b c0 8c 9b } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}