
rule TrojanDownloader_Win32_Bibei_A{
	meta:
		description = "TrojanDownloader:Win32/Bibei.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {72 12 8b 03 0d 20 20 20 20 3d 68 74 74 70 0f 85 } //01 00 
		$a_00_1 = {74 76 6d 65 69 6e 76 2e 63 6e } //01 00  tvmeinv.cn
		$a_03_2 = {eb 1b c7 86 10 01 00 00 90 01 04 eb 1b a1 90 01 04 6a 0a 33 d2 59 f7 f1 83 fa 06 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}