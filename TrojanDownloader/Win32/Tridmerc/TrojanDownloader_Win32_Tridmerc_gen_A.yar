
rule TrojanDownloader_Win32_Tridmerc_gen_A{
	meta:
		description = "TrojanDownloader:Win32/Tridmerc.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {68 04 01 00 00 6a 40 e8 54 00 00 00 8b d8 50 68 04 01 00 00 e8 41 00 00 00 6a 0b 59 8b fb 03 f8 be 90 01 01 03 40 00 f3 a4 51 51 53 68 90 01 01 03 40 00 51 e8 3d 00 00 00 90 00 } //1
		$a_01_1 = {51 53 e8 25 00 00 00 53 e8 19 00 00 00 50 e8 01 00 00 00 cc } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}