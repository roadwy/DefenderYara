
rule TrojanDownloader_Win32_Bredolab_X{
	meta:
		description = "TrojanDownloader:Win32/Bredolab.X,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 14 06 02 14 24 32 d3 88 14 06 40 3d 58 1b 00 00 75 ed 5a 5e 5b c3 90 09 07 00 e8 ?? ?? ?? ?? 33 c0 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}