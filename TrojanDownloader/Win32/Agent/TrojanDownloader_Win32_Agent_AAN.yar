
rule TrojanDownloader_Win32_Agent_AAN{
	meta:
		description = "TrojanDownloader:Win32/Agent.AAN,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 04 00 00 05 00 "
		
	strings :
		$a_03_0 = {09 00 00 00 73 65 74 75 70 2e 65 78 65 00 00 00 ff ff ff ff 26 00 00 00 68 74 74 70 3a 2f 2f 64 6c 2e 64 72 6f 70 62 6f 78 2e 63 6f 6d 2f 90 02 0a 2f 7a 2e 6a 70 67 90 00 } //05 00 
		$a_03_1 = {e8 ed fe ff ff 6a 00 8d 45 f4 8b 4d fc 8b 15 90 01 03 00 e8 90 01 03 ff 8b 45 f4 e8 90 01 03 ff 50 e8 90 01 03 ff 90 00 } //01 00 
		$a_01_2 = {43 3a 5c 50 72 6f 67 74 5c } //01 00 
		$a_01_3 = {43 3a 5c 50 72 6f 67 46 55 47 49 5c } //00 00 
	condition:
		any of ($a_*)
 
}