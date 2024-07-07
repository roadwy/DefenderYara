
rule TrojanDownloader_Win32_Cbeplay_D{
	meta:
		description = "TrojanDownloader:Win32/Cbeplay.D,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {81 c2 be 19 33 01 81 ff 02 21 00 00 74 78 76 15 89 f1 81 fe 56 ae 6f 02 4d be e7 37 8c 02 3a f4 f7 da 3b e9 f8 c1 d6 1c 33 cf f7 d1 f7 d9 33 f0 d6 c1 0b 1f b8 ac d7 43 00 f7 dd 85 c2 84 c4 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}