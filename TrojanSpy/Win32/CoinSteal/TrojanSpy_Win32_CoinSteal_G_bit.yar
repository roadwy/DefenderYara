
rule TrojanSpy_Win32_CoinSteal_G_bit{
	meta:
		description = "TrojanSpy:Win32/CoinSteal.G!bit,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0a 00 04 00 00 "
		
	strings :
		$a_03_0 = {43 32 44 19 ff ff 8d e8 fd ff ff 88 43 ff 75 90 09 06 00 8b 90 01 02 fd ff ff 90 00 } //10
		$a_01_1 = {53 65 74 43 6c 69 70 62 6f 61 72 64 44 61 74 61 } //1 SetClipboardData
		$a_01_2 = {45 6d 70 74 79 43 6c 69 70 62 6f 61 72 64 } //1 EmptyClipboard
		$a_01_3 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 Software\Microsoft\Windows\CurrentVersion\Run
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=10
 
}