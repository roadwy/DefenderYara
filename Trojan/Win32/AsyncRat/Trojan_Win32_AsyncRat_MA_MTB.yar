
rule Trojan_Win32_AsyncRat_MA_MTB{
	meta:
		description = "Trojan:Win32/AsyncRat.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 04 00 00 "
		
	strings :
		$a_01_0 = {c4 01 ed f7 db 4a 8e 52 a5 5a 0c 34 13 21 } //5
		$a_01_1 = {32 2d 41 39 46 43 44 6d 49 67 73 45 66 70 79 63 00 41 31 7d 23 } //5
		$a_01_2 = {63 68 6b 4c 6f 61 64 54 69 70 73 41 74 53 74 61 72 74 75 70 } //1 chkLoadTipsAtStartup
		$a_01_3 = {4d 00 75 00 69 00 75 00 63 00 75 00 72 00 75 00 6f 00 75 00 73 00 75 00 6f 00 75 00 66 00 75 00 74 00 75 00 } //1 Muiucuruousuoufutu
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=12
 
}
rule Trojan_Win32_AsyncRat_MA_MTB_2{
	meta:
		description = "Trojan:Win32/AsyncRat.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_01_0 = {4f 81 cf 00 ff ff ff 47 0f b6 84 3c d8 02 00 00 88 84 34 d8 02 00 00 88 8c 3c d8 02 00 00 0f b6 84 34 d8 02 00 00 8b 4c 24 14 03 c2 0f b6 c0 0f b6 84 04 d8 02 00 00 30 04 0b 43 3b 5c 24 10 72 } //10
		$a_01_1 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 Software\Microsoft\Windows\CurrentVersion\Run
		$a_01_2 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //1 CreateToolhelp32Snapshot
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=12
 
}
rule Trojan_Win32_AsyncRat_MA_MTB_3{
	meta:
		description = "Trojan:Win32/AsyncRat.MA!MTB,SIGNATURE_TYPE_PEHSTR,14 00 14 00 03 00 00 "
		
	strings :
		$a_01_0 = {d2 7f 14 a7 2b cb e4 46 bf 9c 22 d7 55 22 0e df } //10
		$a_01_1 = {94 ca c5 e4 95 b9 a1 40 9a c2 32 36 1a 7d 96 0f 01 } //10
		$a_01_2 = {82 8c 30 ab 9c ca 96 93 19 b6 34 10 a4 89 6c 44 a1 3e fb 30 ad a4 ad af } //10
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10) >=20
 
}