
rule TrojanDownloader_Win32_Tinyloader_A{
	meta:
		description = "TrojanDownloader:Win32/Tinyloader.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 13 3d ac 04 00 00 73 08 83 c0 04 83 c3 04 eb e9 29 c3 31 c0 [0-0f] 31 ?? 81 3b c3 c3 c3 c3 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}