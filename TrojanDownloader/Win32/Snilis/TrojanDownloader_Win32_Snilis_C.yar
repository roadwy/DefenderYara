
rule TrojanDownloader_Win32_Snilis_C{
	meta:
		description = "TrojanDownloader:Win32/Snilis.C,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8a 18 32 5d 90 01 01 ff 75 90 01 01 ff 75 90 01 01 e8 90 01 04 88 18 c7 45 fc 0f 00 00 00 8b 45 90 01 01 83 c0 01 0f 80 c1 00 00 00 89 45 90 01 01 c7 45 fc 10 00 00 00 e9 7e fd ff ff 90 00 } //1
		$a_03_1 = {c7 45 fc 05 00 00 00 33 c0 66 83 3d 90 01 04 02 0f 95 c0 f7 d8 66 89 45 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}