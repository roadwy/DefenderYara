
rule TrojanDownloader_Win32_AsyncRAT_A_MTB{
	meta:
		description = "TrojanDownloader:Win32/AsyncRAT.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {81 ec 10 01 00 00 56 68 00 01 00 00 ff 15 18 90 01 01 40 00 50 ff 15 14 90 01 01 40 00 6a 0f ff 15 10 90 01 01 40 00 50 ff 15 90 01 02 40 00 8b 35 90 01 02 40 00 6a 00 ff d6 8b 00 50 6a 01 6a 04 ff 15 90 01 02 40 00 ff d6 8b 08 8d 54 24 04 51 68 54 90 01 01 40 00 52 ff 15 90 01 02 40 00 83 c4 0c 8d 44 24 04 6a 00 6a 00 50 68 4c 90 01 01 40 00 68 44 90 01 01 40 00 6a 00 ff 15 90 01 02 40 00 6a 00 ff 15 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}