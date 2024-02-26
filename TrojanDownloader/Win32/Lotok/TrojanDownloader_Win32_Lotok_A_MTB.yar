
rule TrojanDownloader_Win32_Lotok_A_MTB{
	meta:
		description = "TrojanDownloader:Win32/Lotok.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {6a 00 8d 8d 00 f0 ff ff 68 00 10 00 00 51 50 ff 15 90 01 04 8b f8 85 ff 7e 90 01 01 8d 85 00 f0 ff ff 57 50 8b 46 04 8d 44 30 10 50 e8 90 01 04 01 7e 04 83 c4 0c 39 5e 04 90 00 } //02 00 
		$a_03_1 = {ff 75 08 ff 15 90 01 04 ff 75 0c 8b f8 66 c7 45 f0 02 00 ff 15 90 01 04 66 89 45 f2 8b 47 0c 6a 10 8b 00 8b 00 89 45 f4 8d 45 f0 50 ff 76 08 ff 15 90 01 04 83 f8 ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}