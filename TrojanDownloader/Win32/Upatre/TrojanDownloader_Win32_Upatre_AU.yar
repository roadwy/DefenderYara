
rule TrojanDownloader_Win32_Upatre_AU{
	meta:
		description = "TrojanDownloader:Win32/Upatre.AU,SIGNATURE_TYPE_PEHSTR_EXT,11 00 11 00 05 00 00 "
		
	strings :
		$a_01_0 = {6a 01 58 48 ab e2 fd } //5
		$a_01_1 = {58 40 40 3d 28 04 00 00 72 05 e9 } //5
		$a_01_2 = {51 33 c9 fc ad ab 8b c1 fc 66 ad 66 ab 8b c1 fc ac 66 ab 59 e2 ea } //5
		$a_00_3 = {25 73 25 73 00 25 73 5c 25 73 00 6f 70 65 6e } //1
		$a_00_4 = {63 68 65 63 6b 69 70 2e 64 79 6e 64 6e 73 2e 6f 72 67 } //1 checkip.dyndns.org
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=17
 
}