
rule TrojanDownloader_Win32_Zlob_gen_AZ{
	meta:
		description = "TrojanDownloader:Win32/Zlob.gen!AZ,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {80 7e 01 3a 88 9d 90 01 02 ff ff b9 ff 00 00 00 8d bd 90 01 02 ff ff f3 ab 66 ab 88 5d ff aa 89 5d 90 01 01 74 31 8d 85 90 01 02 ff ff 50 53 53 6a 25 53 ff 15 90 01 04 56 8d 85 90 01 02 ff ff 50 8d 85 90 01 02 ff ff 68 90 01 04 50 ff 15 90 00 } //01 00 
		$a_01_1 = {39 5d 14 5f 5e 5b 74 10 } //00 00  崹弔孞ၴ
	condition:
		any of ($a_*)
 
}