
rule TrojanDownloader_Win32_Banload_ALI{
	meta:
		description = "TrojanDownloader:Win32/Banload.ALI,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {54 6d 61 63 75 63 6f } //1 Tmacuco
		$a_01_1 = {68 74 74 70 3a 2f 2f 73 33 2e 61 6d 61 7a 6f 6e 61 77 73 2e 63 6f 6d 2f 6d 61 63 61 62 72 6f 30 31 2f } //1 http://s3.amazonaws.com/macabro01/
		$a_01_2 = {47 61 6d 65 20 2d 20 4f 76 65 72 64 75 65 20 4c 6f 61 6e 73 20 2d 20 } //1 Game - Overdue Loans - 
		$a_01_3 = {44 65 6c 70 68 69 42 61 73 69 63 73 20 2d 20 47 61 6d 65 } //1 DelphiBasics - Game
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}