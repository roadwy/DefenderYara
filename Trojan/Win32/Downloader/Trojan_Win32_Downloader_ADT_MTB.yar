
rule Trojan_Win32_Downloader_ADT_MTB{
	meta:
		description = "Trojan:Win32/Downloader.ADT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 04 00 00 0a 00 "
		
	strings :
		$a_01_0 = {8b 6b 04 89 6c 24 04 8b ec 81 ec 1c 01 00 00 a1 14 e0 42 00 33 c5 89 45 fc 56 33 c0 } //0a 00 
		$a_01_1 = {8b 06 89 45 fc 85 c0 74 0b 8b c8 ff 15 2c 71 42 00 ff 55 fc 83 c6 04 47 3b fb 75 e4 } //01 00 
		$a_81_2 = {54 65 6e 73 6f 2e 65 78 65 } //01 00 
		$a_81_3 = {31 39 32 2e 39 35 2e 31 30 2e 31 } //00 00 
	condition:
		any of ($a_*)
 
}