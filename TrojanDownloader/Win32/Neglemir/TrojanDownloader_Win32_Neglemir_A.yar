
rule TrojanDownloader_Win32_Neglemir_A{
	meta:
		description = "TrojanDownloader:Win32/Neglemir.A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 05 00 06 00 00 "
		
	strings :
		$a_03_0 = {eb 0c 68 d0 07 00 00 e8 90 01 04 eb 90 01 01 33 c0 5a 59 59 64 89 10 68 90 00 } //2
		$a_01_1 = {63 3a 5c 77 69 6e 64 6f 77 73 5c 68 65 6c 70 5c 77 69 6e 68 65 6c 70 2e 65 78 65 } //2 c:\windows\help\winhelp.exe
		$a_01_2 = {2f 6a 2e 6a 73 70 3f 70 } //1 /j.jsp?p
		$a_03_3 = {26 70 33 3d 90 01 0c 26 70 34 3d 90 00 } //1
		$a_01_4 = {2f 61 64 64 2e 6a 73 70 3f 75 69 64 3d } //1 /add.jsp?uid=
		$a_03_5 = {26 76 65 72 3d 90 01 05 26 6d 61 63 3d 90 00 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1+(#a_01_4  & 1)*1+(#a_03_5  & 1)*1) >=5
 
}