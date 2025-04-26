
rule TrojanDownloader_Win32_Coins_BBX_MTB{
	meta:
		description = "TrojanDownloader:Win32/Coins.BBX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {69 48 18 fd 43 03 00 81 c1 c3 9e 26 00 89 48 18 c1 e9 10 81 e1 ff 7f 00 00 8b c1 c3 } //1
		$a_01_1 = {50 68 80 00 00 00 6a 02 50 50 68 00 00 00 40 57 8a d8 ff 15 } //1
		$a_01_2 = {d1 e9 8b d1 81 f2 20 83 b8 ed 24 01 0f 44 d1 83 eb 01 } //1
		$a_01_3 = {66 00 77 00 33 00 2e 00 65 00 78 00 65 00 } //1 fw3.exe
		$a_01_4 = {66 00 77 00 25 00 64 00 2e 00 65 00 78 00 65 00 } //1 fw%d.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}