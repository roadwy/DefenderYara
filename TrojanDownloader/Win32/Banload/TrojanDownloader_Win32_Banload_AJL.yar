
rule TrojanDownloader_Win32_Banload_AJL{
	meta:
		description = "TrojanDownloader:Win32/Banload.AJL,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0a 00 07 00 00 "
		
	strings :
		$a_01_0 = {7e 2b be 01 00 00 00 8d 45 f0 8b d7 52 8b 55 fc 8a 54 32 ff 59 2a d1 f6 d2 e8 } //4
		$a_01_1 = {97 8b 8b 8f c5 d0 d0 9b 9e 88 9e 8b 9a 96 8c 93 9e 92 96 d1 91 9a 8b d0 97 8b 92 93 d0 99 90 91 8b 8c d0 } //4
		$a_01_2 = {8b 9e 8c 94 94 96 93 93 df d0 99 df d0 b6 b2 df be 89 9e 8c } //2
		$a_01_3 = {bc c5 a3 be 8d 8e 8a 96 89 90 8c df 9b 9a df 8f 8d 90 98 8d } //2
		$a_01_4 = {9e 92 9e 8c a3 b6 91 8b 9a 8d 91 9a 8b df ba 87 8f 93 90 8d } //2
		$a_01_5 = {9c c5 a3 af 8d 90 98 8d 9e 92 bb 9e 8b 9e a3 00 } //1
		$a_01_6 = {89 96 8c 8b 9e d1 9c 90 92 00 } //1
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*4+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=10
 
}