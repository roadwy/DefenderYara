
rule TrojanDownloader_Win32_Omexo_B{
	meta:
		description = "TrojanDownloader:Win32/Omexo.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {75 0b 8b 49 50 51 50 ff 15 } //1
		$a_01_1 = {f7 d0 33 d2 f7 74 24 04 8b c2 c2 04 00 } //1
		$a_01_2 = {3d 31 04 00 00 75 1b 6a 00 6a 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}