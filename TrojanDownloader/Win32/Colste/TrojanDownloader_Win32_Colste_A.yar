
rule TrojanDownloader_Win32_Colste_A{
	meta:
		description = "TrojanDownloader:Win32/Colste.A,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 05 00 00 "
		
	strings :
		$a_03_0 = {55 8b ec 8b 45 08 80 38 00 74 0b 8b c8 80 31 ?? 41 80 39 00 75 f7 5d c3 } //10
		$a_03_1 = {68 50 93 08 00 57 ff ?? ?? 53 e8 ?? ?? ?? ?? 68 50 93 08 00 ff ?? ?? 57 e8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 56 e8 } //5
		$a_03_2 = {68 b8 88 00 00 ff 15 ?? ?? ?? ?? 68 ?? ?? ?? ?? ff 15 } //5
		$a_03_3 = {5c 78 77 69 6e 6d 6f 6e 00 [0-20] 5c 77 69 6e 6d 6f 6e 36 34 2e 65 78 65 } //1
		$a_01_4 = {5c 78 70 6d 77 69 6e 33 32 2e 65 78 65 } //1 \xpmwin32.exe
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*5+(#a_03_2  & 1)*5+(#a_03_3  & 1)*1+(#a_01_4  & 1)*1) >=16
 
}