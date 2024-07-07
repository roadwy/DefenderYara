
rule TrojanDownloader_Win32_Swizzor_gen_K{
	meta:
		description = "TrojanDownloader:Win32/Swizzor.gen!K,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {03 c3 99 f7 3d 90 01 04 a1 90 01 04 83 45 fc 02 32 0c 02 8b 45 fc 88 0e 46 3b 45 f8 7c b3 90 00 } //1
		$a_01_1 = {83 fb 5a 7e d9 39 75 d4 75 07 c7 45 d4 19 2e 00 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}