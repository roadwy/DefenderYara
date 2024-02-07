
rule TrojanDownloader_Win32_Swity_C{
	meta:
		description = "TrojanDownloader:Win32/Swity.C,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {66 74 70 6c 69 73 74 61 72 61 72 71 75 69 76 6f 73 00 } //01 00  瑦汰獩慴慲煲極潶s
		$a_01_1 = {6c 69 71 75 69 64 61 72 74 6f 64 6f 73 6f 73 64 61 64 6f 73 69 65 63 68 72 6f 6d 65 00 } //01 00 
		$a_03_2 = {89 45 dc 8d 4d c4 51 8d 55 c8 52 6a 02 90 09 27 00 8d 4d c8 ff 15 90 01 04 50 68 90 01 04 ff 15 90 01 04 8b d0 8d 4d c4 ff 15 90 01 04 50 ff 15 90 00 } //01 00 
		$a_03_3 = {e9 03 02 00 00 8b 55 0c 8d 4e 58 8b 02 50 51 ff 15 90 01 04 8b 17 68 90 01 04 52 ff 15 90 00 } //00 00 
		$a_00_4 = {80 10 } //00 00 
	condition:
		any of ($a_*)
 
}