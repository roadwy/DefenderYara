
rule TrojanDownloader_Win32_Joulwo_A{
	meta:
		description = "TrojanDownloader:Win32/Joulwo.A,SIGNATURE_TYPE_PEHSTR_EXT,08 00 07 00 07 00 00 03 00 "
		
	strings :
		$a_03_0 = {53 68 00 00 00 02 6a 03 53 6a 01 68 00 00 00 80 50 ff 15 90 01 03 10 6a 02 8b f8 53 68 38 ff ff ff 57 ff 15 90 01 03 10 8d 45 e8 53 50 8d 85 d8 fe ff ff 68 c8 00 00 00 50 57 90 00 } //02 00 
		$a_03_1 = {68 98 3a 00 00 56 6a 02 e8 90 01 02 ff ff 85 c0 56 74 90 01 01 68 00 01 00 00 ff 15 90 00 } //03 00 
		$a_03_2 = {68 00 28 00 00 50 ff 74 24 38 ff 15 90 01 03 10 83 f8 01 0f 85 90 01 03 00 bd 70 5a 00 10 55 e8 90 01 03 00 59 b9 fb 27 00 00 2b 90 00 } //01 00 
		$a_01_3 = {5b 50 61 73 73 77 6f 72 64 5d } //01 00  [Password]
		$a_01_4 = {5b 42 61 63 6b 75 70 5d } //01 00  [Backup]
		$a_01_5 = {5b 73 65 72 76 65 72 31 5d } //01 00  [server1]
		$a_01_6 = {5b 50 72 69 6d 61 72 79 5d } //00 00  [Primary]
	condition:
		any of ($a_*)
 
}