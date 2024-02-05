
rule TrojanDownloader_Win32_Zamelcat_A{
	meta:
		description = "TrojanDownloader:Win32/Zamelcat.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {6a 1a 99 59 f7 f9 8d 45 08 50 53 83 c2 61 89 55 08 e8 90 01 01 00 00 00 59 4f 59 75 df 90 00 } //01 00 
		$a_03_1 = {6a 03 e8 80 ff ff ff 50 8d 85 90 01 02 ff ff 50 68 90 01 04 8d 85 90 01 02 ff ff 56 50 ff 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}