
rule TrojanDownloader_Win32_Rugmi_HNT_MTB{
	meta:
		description = "TrojanDownloader:Win32/Rugmi.HNT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 45 08 89 45 f8 8b 45 10 89 45 fc 8b 45 10 48 89 45 10 83 7d fc 00 74 1a 8b 45 08 8b 4d 0c 8a 09 88 08 8b 45 08 40 89 45 08 8b 45 0c 40 89 45 0c } //5
		$a_01_1 = {55 8b ec 51 51 8b 45 08 89 45 fc 8b 45 0c 89 45 f8 8b 45 0c 48 89 45 0c 83 7d f8 00 76 0f 8b 45 fc c6 00 00 8b 45 fc 40 89 45 fc eb de 8b 45 08 8b e5 5d c3 } //2
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*2) >=7
 
}