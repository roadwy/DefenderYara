
rule TrojanDownloader_Win32_Bredolab_A{
	meta:
		description = "TrojanDownloader:Win32/Bredolab.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {80 36 ef 46 e2 fa 8b 0d 90 01 02 40 00 8b 35 90 01 02 40 00 80 3e 0d 75 03 c6 06 00 80 3e 0a 75 03 c6 06 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}