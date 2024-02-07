
rule TrojanDownloader_Win32_Banload_AYE{
	meta:
		description = "TrojanDownloader:Win32/Banload.AYE,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {24 31 74 33 5f 40 73 70 61 6d 40 } //01 00  $1t3_@spam@
		$a_01_1 = {2f 00 78 00 6d 00 6c 00 2f 00 6a 00 6f 00 6e 00 2f 00 79 00 66 00 63 00 73 00 78 00 66 00 64 00 2e 00 7a 00 69 00 70 00 } //01 00  /xml/jon/yfcsxfd.zip
		$a_01_2 = {5c 00 79 00 66 00 63 00 73 00 78 00 66 00 64 00 2e 00 65 00 78 00 65 00 } //01 00  \yfcsxfd.exe
		$a_03_3 = {8b 45 f8 8b 08 ff 51 34 33 d2 8b 45 f8 e8 90 01 04 8b 45 f8 83 c0 54 8b 15 90 01 04 e8 90 01 04 6a 00 b9 bf 28 00 00 ba 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}