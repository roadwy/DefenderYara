
rule TrojanDownloader_Win32_Momole{
	meta:
		description = "TrojanDownloader:Win32/Momole,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {b8 7a f1 02 00 3b f0 7f 2e 6a 00 8b c6 03 c3 0f 80 9e 00 00 00 50 53 6a 03 8d 45 d0 50 6a 04 57 e8 ef 33 f9 ff 83 c4 1c 6a 01 58 03 c6 0f 80 80 00 00 00 8b f0 eb c9 } //01 00 
		$a_01_1 = {02 47 02 66 0f fc ea 0f f8 c4 0f ec eb ff e0 } //00 00 
		$a_00_2 = {5d } //04 00 
	condition:
		any of ($a_*)
 
}