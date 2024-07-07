
rule TrojanDownloader_Win32_Flexty_A{
	meta:
		description = "TrojanDownloader:Win32/Flexty.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {78 79 42 6f 74 2e 65 78 65 00 73 74 72 64 75 70 } //1
		$a_03_1 = {0f b6 4e 02 c1 e3 08 b8 90 01 04 c6 06 01 03 d9 8d 50 01 8a 08 40 84 c9 75 f9 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}