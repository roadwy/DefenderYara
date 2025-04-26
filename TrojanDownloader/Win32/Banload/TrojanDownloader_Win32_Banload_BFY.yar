
rule TrojanDownloader_Win32_Banload_BFY{
	meta:
		description = "TrojanDownloader:Win32/Banload.BFY,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {74 6d 72 56 65 72 66 54 69 6d 65 72 } //1 tmrVerfTimer
		$a_01_1 = {74 6d 72 42 61 69 78 61 54 69 6d 65 72 } //1 tmrBaixaTimer
		$a_01_2 = {78 2e 67 69 66 } //1 x.gif
		$a_01_3 = {75 4d 6f 64 41 76 73 } //1 uModAvs
		$a_03_4 = {b9 03 00 00 00 33 d2 e8 ?? ?? ?? ff ff 75 e8 68 ?? ?? 47 00 8b 45 fc 05 0c 03 00 00 ba 03 00 00 00 e8 ?? ?? f8 ff } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*1) >=4
 
}