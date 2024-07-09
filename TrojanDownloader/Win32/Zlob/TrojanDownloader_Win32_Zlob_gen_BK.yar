
rule TrojanDownloader_Win32_Zlob_gen_BK{
	meta:
		description = "TrojanDownloader:Win32/Zlob.gen!BK,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 04 00 00 "
		
	strings :
		$a_03_0 = {83 e8 4e 74 ?? 83 e8 33 74 ?? 2d 90 90 00 00 00 (75|0f 85) } //1
		$a_01_1 = {6a 16 68 2d 01 00 00 } //1
		$a_01_2 = {66 67 64 79 2e 64 6c 6c 00 44 6c 6c } //2 杦祤搮汬䐀汬
		$a_01_3 = {68 6c 65 6f 2e 64 6c 6c 00 44 6c 6c } //2 汨潥搮汬䐀汬
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=3
 
}