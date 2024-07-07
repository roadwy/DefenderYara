
rule TrojanDownloader_Win32_Aningik_A{
	meta:
		description = "TrojanDownloader:Win32/Aningik.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {89 45 fc 8b 7d fc b8 5b 5a 6f 6e 89 07 b8 65 54 72 61 89 47 04 b8 6e 73 66 65 } //1
		$a_01_1 = {53 68 80 00 00 00 6a 04 53 6a 07 68 00 00 00 40 8d 8d 28 fd ff ff 51 ff d0 8b f0 83 fe ff 0f 84 80 00 00 00 } //1
		$a_01_2 = {8d 45 bc 50 ff d7 85 c0 75 06 46 83 fe 05 7c f0 8b fb } //1
		$a_01_3 = {2f 72 2e 70 68 70 3f 66 3d 65 } //1 /r.php?f=e
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}