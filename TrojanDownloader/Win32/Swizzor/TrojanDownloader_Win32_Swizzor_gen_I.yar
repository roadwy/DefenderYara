
rule TrojanDownloader_Win32_Swizzor_gen_I{
	meta:
		description = "TrojanDownloader:Win32/Swizzor.gen!I,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {81 74 24 0c 83 19 89 12 6a 00 8d 54 24 14 52 68 20 04 00 00 } //1
		$a_03_1 = {68 00 02 00 00 90 01 1b 8b 52 78 6a 00 90 01 06 ff d2 90 01 06 8b 51 70 68 00 22 00 00 50 ff d2 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}