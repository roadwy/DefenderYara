
rule TrojanDownloader_Win32_Bowkits_A{
	meta:
		description = "TrojanDownloader:Win32/Bowkits.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {85 c0 74 2f 68 90 01 02 40 00 a1 90 01 02 40 00 50 e8 90 01 02 ff ff 85 c0 75 09 33 c0 a3 90 01 02 40 00 eb 12 6a ff 90 00 } //01 00 
		$a_01_1 = {8a 00 2c 21 74 0e 04 fe 2c 02 72 08 2c 06 0f 85 } //02 00 
		$a_01_2 = {6b 69 77 69 62 6f 74 33 00 } //00 00 
	condition:
		any of ($a_*)
 
}