
rule TrojanDownloader_Win32_Upatre_CO{
	meta:
		description = "TrojanDownloader:Win32/Upatre.CO,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {c6 00 68 40 89 08 c6 40 04 c3 8b 85 90 01 02 ff ff 50 89 85 90 01 02 ff ff ff b5 90 01 02 ff ff ff 55 bc 90 00 } //01 00 
		$a_01_1 = {8b 07 51 8b c8 33 0e 40 40 46 40 40 88 0f 59 47 4b 75 04 5b 2b f3 53 e2 e7 } //01 00 
		$a_01_2 = {66 ad 52 03 d0 3b fa 72 04 41 5a eb f3 } //00 00 
	condition:
		any of ($a_*)
 
}