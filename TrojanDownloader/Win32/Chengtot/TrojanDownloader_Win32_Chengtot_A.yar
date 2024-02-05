
rule TrojanDownloader_Win32_Chengtot_A{
	meta:
		description = "TrojanDownloader:Win32/Chengtot.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {6a 00 6a 00 6a 01 68 90 01 03 00 ff 33 68 90 01 03 00 ff 35 90 01 04 68 90 01 03 00 ff 33 68 90 01 03 00 ff 33 68 90 01 03 00 ff 33 68 90 01 03 00 ff 33 68 90 01 03 00 ff 33 68 90 01 03 00 68 90 01 03 00 ff 35 90 01 04 68 90 01 03 00 8d 45 fc ba 12 00 00 00 e8 90 01 02 fe ff 8b 45 fc 50 ff 35 90 01 04 68 90 01 03 00 ff 33 68 90 01 03 00 ff 33 68 90 01 03 00 8d 45 f8 ba 06 00 00 00 90 00 } //01 00 
		$a_02_1 = {68 74 74 70 90 02 30 3a 2f 2f 90 02 30 64 72 90 02 20 76 90 02 20 33 32 90 02 20 2e 90 02 20 64 61 74 61 90 02 35 2e 65 90 02 20 78 90 02 20 65 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}