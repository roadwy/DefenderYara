
rule TrojanDownloader_Win32_Remetrac_A{
	meta:
		description = "TrojanDownloader:Win32/Remetrac.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {b8 72 00 00 00 e8 90 01 02 ff ff ff b5 90 01 02 ff ff 8d 95 90 01 02 ff ff b8 65 00 00 00 e8 90 01 02 ff ff ff b5 90 01 02 ff ff 8d 95 90 01 02 ff ff b8 63 00 00 00 90 00 } //01 00 
		$a_01_1 = {8b d6 83 c2 04 88 02 c6 03 e9 47 8b 45 f4 89 07 8d 45 f0 50 8b 45 f0 50 6a 05 53 e8 } //00 00 
	condition:
		any of ($a_*)
 
}