
rule TrojanDownloader_Win32_Oyolop_A{
	meta:
		description = "TrojanDownloader:Win32/Oyolop.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b 4d f4 c1 e1 06 89 4d f4 90 90 90 8b 55 fc 0f be 42 02 83 f8 3d } //1
		$a_01_1 = {b9 09 00 00 00 33 c0 8d bd 09 70 ff ff f3 ab 66 ab aa 8d 85 00 a0 ff ff 50 } //1
		$a_01_2 = {8b 45 f4 c1 e0 06 89 45 f4 8b 4d fc 8a 51 01 52 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}