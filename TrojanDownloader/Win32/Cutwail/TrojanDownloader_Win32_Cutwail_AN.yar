
rule TrojanDownloader_Win32_Cutwail_AN{
	meta:
		description = "TrojanDownloader:Win32/Cutwail.AN,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8a 54 08 ff 30 14 08 48 75 f6 80 31 } //1
		$a_03_1 = {74 1a 8d 4d e8 51 50 8b 46 04 05 ?? ?? ?? ?? 50 8b 46 fc 03 45 f8 50 ff 75 08 ff d7 8b 45 f4 0f b7 40 02 ff 45 fc 83 c6 28 39 45 fc 7c ce } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}