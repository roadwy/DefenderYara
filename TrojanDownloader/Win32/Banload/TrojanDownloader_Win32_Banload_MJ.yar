
rule TrojanDownloader_Win32_Banload_MJ{
	meta:
		description = "TrojanDownloader:Win32/Banload.MJ,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f b6 44 38 ff 89 45 90 01 01 b8 90 01 04 0f b6 44 18 ff 89 45 90 01 01 8d 45 90 01 01 8b 55 90 01 01 2b 55 90 00 } //01 00 
		$a_01_1 = {0b 54 46 72 6d 53 70 6f 6f 6c 56 41 } //00 00  吋牆卭潰汯䅖
	condition:
		any of ($a_*)
 
}