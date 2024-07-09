
rule TrojanDownloader_Win32_Fikoter_A{
	meta:
		description = "TrojanDownloader:Win32/Fikoter.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8a d3 80 c2 43 52 e8 ?? ?? ?? ?? 83 c4 04 85 c0 75 0d fe c3 80 fb 04 7c e7 } //1
		$a_01_1 = {8b ca 83 e1 03 f3 a4 89 43 f8 8b 4c 24 24 8b 44 24 10 40 83 c3 28 8b 11 33 c9 89 44 24 10 66 8b 4a 06 3b c1 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}