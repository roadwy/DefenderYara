
rule TrojanDownloader_Win64_Lazy_RDA_MTB{
	meta:
		description = "TrojanDownloader:Win64/Lazy.RDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 06 00 00 02 00 "
		
	strings :
		$a_01_0 = {b8 33 01 00 00 66 03 c2 66 33 c1 } //02 00 
		$a_03_1 = {48 63 c2 48 8d 4d 90 01 01 48 03 c8 8d 42 90 01 01 30 01 ff c2 83 fa 90 00 } //01 00 
		$a_01_2 = {77 61 73 64 2d } //01 00  wasd-
		$a_01_3 = {2f 2f 63 64 6e 2e 64 69 73 63 6f 72 64 61 70 70 2e 63 6f 6d 2f 61 74 74 61 63 68 6d 65 6e 74 73 } //01 00  //cdn.discordapp.com/attachments
		$a_01_4 = {63 68 72 6f 6d 65 2e 65 78 65 } //01 00  chrome.exe
		$a_01_5 = {46 6f 72 74 6e 69 74 65 } //00 00  Fortnite
	condition:
		any of ($a_*)
 
}