
rule TrojanDownloader_Win32_Dogrobot_B{
	meta:
		description = "TrojanDownloader:Win32/Dogrobot.B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b f0 81 ee cf 02 00 00 81 fe 00 00 00 10 0f 87 90 01 02 00 00 53 57 6a 00 6a 00 68 cf 02 00 00 55 ff 15 90 00 } //01 00 
		$a_01_1 = {72 75 62 62 69 73 68 5c 64 6e 6c 6f 61 65 72 63 5c 52 65 6c 65 61 73 65 5c 64 6e 6c 6f 61 64 65 72 63 2e 70 64 62 } //00 00 
	condition:
		any of ($a_*)
 
}