
rule TrojanDownloader_Win32_Bredolab_A{
	meta:
		description = "TrojanDownloader:Win32/Bredolab.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {80 36 ef 46 e2 fa 8b 0d ?? ?? 40 00 8b 35 ?? ?? 40 00 80 3e 0d 75 03 c6 06 00 80 3e 0a 75 03 c6 06 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}