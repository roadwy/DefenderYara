
rule TrojanDownloader_Win32_Zbot_G{
	meta:
		description = "TrojanDownloader:Win32/Zbot.G,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {22 00 00 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 2e 00 58 00 4d 00 4c 00 48 00 54 00 54 00 50 00 00 00 06 00 00 00 47 00 45 00 54 00 00 00 4f 00 70 00 65 00 6e 00 00 00 } //01 00 
		$a_03_1 = {f5 00 00 00 00 1b 0a 00 04 90 01 01 ff 0a 0b 00 0c 00 04 90 1b 00 ff fc 34 fc f8 64 ff 35 90 1b 00 ff 3a 90 01 01 ff 0c 00 25 6c 0c 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}