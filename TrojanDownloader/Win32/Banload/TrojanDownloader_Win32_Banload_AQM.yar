
rule TrojanDownloader_Win32_Banload_AQM{
	meta:
		description = "TrojanDownloader:Win32/Banload.AQM,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {ff 2d f4 1e 70 64 ff 28 30 ff 01 00 fc f6 50 ff f3 ff 00 70 66 ff 1b ?? 00 43 74 ff 28 10 ff 01 00 04 40 ff 80 0c 00 4a fd 69 20 ff fe 68 f0 fe 77 01 0a ?? 00 00 00 04 50 ff 28 30 ff 01 00 fb 9c e0 fe } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}