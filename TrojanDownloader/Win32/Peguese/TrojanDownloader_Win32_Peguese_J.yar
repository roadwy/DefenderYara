
rule TrojanDownloader_Win32_Peguese_J{
	meta:
		description = "TrojanDownloader:Win32/Peguese.J,SIGNATURE_TYPE_PEHSTR_EXT,1a 00 1a 00 06 00 00 05 00 "
		
	strings :
		$a_01_0 = {2e 63 70 6c 00 43 50 6c 41 70 70 6c 65 74 00 } //05 00 
		$a_01_1 = {06 74 6d 72 49 6e 69 fc 02 } //05 00 
		$a_01_2 = {0c 74 6d 72 42 6c 6f 71 54 69 6d 65 72 12 } //05 00 
		$a_01_3 = {0a 74 6d 72 46 32 54 69 6d 65 72 11 } //05 00 
		$a_01_4 = {0b 74 6d 72 45 73 63 54 69 6d 65 72 } //01 00 
		$a_03_5 = {8b 08 ff 51 1c 8b 85 90 01 02 ff ff 50 8d 95 90 01 02 ff ff b8 90 01 03 00 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}