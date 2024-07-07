
rule TrojanDownloader_Win32_Hupigon_B{
	meta:
		description = "TrojanDownloader:Win32/Hupigon.B,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {60 00 10 ff 15 08 50 00 10 8b f8 68 90 01 01 60 00 10 57 ff 15 04 50 00 10 8b f0 6a 00 6a 00 68 90 01 01 60 00 10 68 90 01 01 60 00 10 6a 00 ff d6 83 c4 14 85 c0 74 e7 57 ff 15 00 50 00 10 5f 5e c3 8b 44 24 08 83 f8 01 0f 85 88 00 00 00 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}