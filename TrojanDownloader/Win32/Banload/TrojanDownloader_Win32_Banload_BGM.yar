
rule TrojanDownloader_Win32_Banload_BGM{
	meta:
		description = "TrojanDownloader:Win32/Banload.BGM,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {2e 00 7a 00 69 00 70 00 90 02 10 6f 00 70 00 65 00 6e 00 90 00 } //1
		$a_03_1 = {50 ff d6 6a 00 6a 00 8d 84 24 50 04 00 00 50 68 90 01 02 41 00 6a 00 ff 15 90 01 02 41 00 85 c0 0f 85 90 01 02 00 00 83 ec 08 8d 8c 24 50 04 00 00 90 00 } //10
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*10) >=11
 
}