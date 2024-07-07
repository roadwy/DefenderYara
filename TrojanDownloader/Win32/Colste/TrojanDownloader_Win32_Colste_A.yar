
rule TrojanDownloader_Win32_Colste_A{
	meta:
		description = "TrojanDownloader:Win32/Colste.A,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 05 00 00 "
		
	strings :
		$a_03_0 = {55 8b ec 8b 45 08 80 38 00 74 0b 8b c8 80 31 90 01 01 41 80 39 00 75 f7 5d c3 90 00 } //10
		$a_03_1 = {68 50 93 08 00 57 ff 90 01 02 53 e8 90 01 04 68 50 93 08 00 ff 90 01 02 57 e8 90 01 04 68 90 01 04 56 e8 90 00 } //5
		$a_03_2 = {68 b8 88 00 00 ff 15 90 01 04 68 90 01 04 ff 15 90 00 } //5
		$a_03_3 = {5c 78 77 69 6e 6d 6f 6e 00 90 02 20 5c 77 69 6e 6d 6f 6e 36 34 2e 65 78 65 90 00 } //1
		$a_01_4 = {5c 78 70 6d 77 69 6e 33 32 2e 65 78 65 } //1 \xpmwin32.exe
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*5+(#a_03_2  & 1)*5+(#a_03_3  & 1)*1+(#a_01_4  & 1)*1) >=16
 
}