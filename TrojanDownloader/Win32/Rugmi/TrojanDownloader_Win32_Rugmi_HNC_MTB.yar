
rule TrojanDownloader_Win32_Rugmi_HNC_MTB{
	meta:
		description = "TrojanDownloader:Win32/Rugmi.HNC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 04 00 00 "
		
	strings :
		$a_01_0 = {8b 74 11 fc 01 c6 89 74 13 04 83 c2 04 81 fa fc 5f 00 00 72 eb } //1
		$a_01_1 = {03 43 0c 01 d8 01 d3 89 1c 24 ff d0 c7 04 24 00 00 00 00 ff 15 } //1
		$a_01_2 = {8b 44 24 1c 33 d2 66 89 14 48 89 44 24 24 8d 04 33 89 44 24 20 8d 44 24 20 50 c6 44 24 2c 01 ff d7 } //1
		$a_01_3 = {8b 55 fc 0f be 02 03 45 fc 89 45 fc 8b 4d fc 83 c1 01 51 ff 55 b0 89 45 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=1
 
}