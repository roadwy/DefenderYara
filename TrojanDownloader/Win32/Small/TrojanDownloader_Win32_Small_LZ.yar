
rule TrojanDownloader_Win32_Small_LZ{
	meta:
		description = "TrojanDownloader:Win32/Small.LZ,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {81 ec 68 01 00 00 56 68 90 01 04 ff 15 90 01 04 68 90 01 04 50 a3 90 01 04 ff 15 90 01 04 6a 00 6a 00 68 90 01 04 68 90 01 04 6a 00 a3 90 01 04 ff d0 8d 84 24 08 01 00 00 50 6a 64 ff 15 90 01 04 68 90 01 04 68 90 01 04 e8 90 01 04 8d 4c 24 48 8b f0 51 68 90 01 04 56 e8 90 01 04 83 c4 14 83 f8 01 0f 85 8f 00 00 00 57 8b 3d 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}