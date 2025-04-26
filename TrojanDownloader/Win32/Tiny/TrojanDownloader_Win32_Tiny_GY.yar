
rule TrojanDownloader_Win32_Tiny_GY{
	meta:
		description = "TrojanDownloader:Win32/Tiny.GY,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {a6 b5 c0 d7 a0 a2 af 1d 12 32 3e 51 5e 55 79 25 97 9f 82 b8 e5 de c2 8c fa ed 52 1f 0a 25 77 52 13 } //1
		$a_01_1 = {99 88 fa ee d4 c8 d4 5d 22 15 } //1
		$a_01_2 = {87 af c0 c2 e8 e3 e5 07 29 29 29 51 73 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}