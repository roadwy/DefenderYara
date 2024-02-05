
rule TrojanDownloader_Win32_Zlob_AEQ{
	meta:
		description = "TrojanDownloader:Win32/Zlob.AEQ,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {74 0d 8b 45 f4 46 83 c0 f8 3b f0 72 98 eb 63 53 53 81 c6 6a ff ff ff 56 ff 75 f8 ff 15 } //05 00 
		$a_01_1 = {74 15 80 c2 64 2b f8 53 8a da 32 d9 88 1e 46 8a 0c 37 84 c9 75 f2 } //01 00 
		$a_03_2 = {ff 55 f8 8b 45 fc 29 45 10 3b c6 74 c7 53 ff 15 90 01 04 39 7d 10 75 05 33 c0 40 eb 02 90 00 } //01 00 
		$a_01_3 = {72 d6 eb 52 8b 45 0c 53 53 05 74 ff ff ff 50 ff 75 14 ff 15 } //00 00 
	condition:
		any of ($a_*)
 
}