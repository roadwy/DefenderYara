
rule TrojanDownloader_Win32_Stration_gen_I{
	meta:
		description = "TrojanDownloader:Win32/Stration.gen!I,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {40 83 f8 1f 7c f5 (68|b9) d0 07 00 00 e8 90 09 0b 00 80 74 04 } //1
		$a_11_1 = {3d 72 75 6e 3d 2d 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_11_1  & 1)*1) >=2
 
}