
rule TrojanDownloader_Win32_Alien_AYA_MTB{
	meta:
		description = "TrojanDownloader:Win32/Alien.AYA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_01_0 = {6c 76 6d 61 79 2e 74 6f 70 } //2 lvmay.top
		$a_01_1 = {64 64 6a 6d 2e 74 6f 70 } //1 ddjm.top
		$a_01_2 = {51 33 4a 6c 59 58 52 6c 55 48 4a 76 59 32 56 7a 63 30 45 3d } //1 Q3JlYXRlUHJvY2Vzc0E=
		$a_01_3 = {25 73 5c 74 65 6d 70 5c 25 64 2e 62 61 6b } //1 %s\temp\%d.bak
		$a_00_4 = {55 00 73 00 65 00 72 00 73 00 2f 00 50 00 75 00 62 00 6c 00 69 00 63 00 2f 00 57 00 49 00 4e 00 57 00 4f 00 52 00 44 00 2e 00 65 00 78 00 65 00 } //1 Users/Public/WINWORD.exe
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_00_4  & 1)*1) >=6
 
}