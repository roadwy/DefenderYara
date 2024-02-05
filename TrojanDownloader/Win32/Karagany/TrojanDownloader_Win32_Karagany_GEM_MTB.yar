
rule TrojanDownloader_Win32_Karagany_GEM_MTB{
	meta:
		description = "TrojanDownloader:Win32/Karagany.GEM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 03 00 00 0a 00 "
		
	strings :
		$a_01_0 = {8a 14 01 ff 45 0c 88 10 8b 55 0c 40 3b 53 50 72 ef } //0a 00 
		$a_01_1 = {8d 7c 15 e4 0f b6 1f 33 d9 03 d8 42 88 1f 83 fa 07 72 ed } //0a 00 
		$a_01_2 = {8b 45 20 8b 80 c8 01 00 00 8b 00 33 c6 2b c7 8b 45 20 75 16 8b 4d 20 8b 89 cc 01 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}