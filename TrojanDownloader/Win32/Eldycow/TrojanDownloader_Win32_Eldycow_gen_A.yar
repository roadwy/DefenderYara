
rule TrojanDownloader_Win32_Eldycow_gen_A{
	meta:
		description = "TrojanDownloader:Win32/Eldycow.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_00_0 = {60 8b 6c 24 24 81 7d 00 90 90 90 90 74 58 8b 45 00 8b 5d 04 b9 20 00 00 00 ba 20 37 ef c6 } //1
		$a_00_1 = {e2 ee ff d3 5b 31 c0 c2 0c 00 60 8b 6c 24 24 8b 45 00 8b 5d 04 b9 20 00 00 00 ba 20 37 ef c6 } //1
		$a_02_2 = {39 df 76 f2 5b c6 07 e9 89 57 01 50 54 6a 40 68 00 10 00 00 ff 75 08 ff 93 ?? ?? 00 00 59 09 c0 74 11 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_02_2  & 1)*1) >=1
 
}