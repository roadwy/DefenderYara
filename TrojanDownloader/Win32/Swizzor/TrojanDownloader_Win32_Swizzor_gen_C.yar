
rule TrojanDownloader_Win32_Swizzor_gen_C{
	meta:
		description = "TrojanDownloader:Win32/Swizzor.gen!C,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {2e 00 00 00 90 02 05 0f 00 00 00 90 02 20 b8 2e 00 00 00 90 02 0a b9 0f 00 00 00 90 00 } //01 00 
		$a_03_1 = {8b 4a 3c 01 90 01 01 8b 51 7c 8b 90 01 01 78 90 00 } //01 00 
		$a_03_2 = {7f 02 00 00 0f 8d 90 02 10 81 90 01 01 7f 00 00 00 0f 8f 90 09 02 00 90 00 } //0a 00 
		$a_03_3 = {85 c0 0f 84 90 02 1a c1 90 01 01 05 c1 2d 90 01 03 00 1b 0b 90 01 04 00 90 03 03 06 83 e8 41 81 e8 41 00 00 00 01 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}