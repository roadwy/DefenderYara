
rule TrojanDownloader_Win32_Delf_ZXX_bit{
	meta:
		description = "TrojanDownloader:Win32/Delf.ZXX!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {7e 22 bb 01 00 00 00 8d 45 90 01 01 e8 90 01 04 8b 55 90 01 01 0f b7 54 5a fe 66 83 f2 90 01 01 66 89 54 58 fe 43 4e 75 e3 90 00 } //1
		$a_03_1 = {6a 05 6a 00 6a 00 a1 90 01 04 e8 90 01 04 50 68 90 01 04 6a 00 e8 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}