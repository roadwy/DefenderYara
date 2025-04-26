
rule TrojanDownloader_Win32_Banload_ATE{
	meta:
		description = "TrojanDownloader:Win32/Banload.ATE,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {43 00 34 00 50 00 35 00 45 00 33 00 4b 00 6e 00 43 00 4a 00 4c 00 31 00 43 00 4b 00 4f 00 73 00 00 00 } //1
		$a_01_1 = {54 00 45 00 4d 00 50 00 00 00 00 00 b0 04 02 00 ff ff ff ff 08 00 00 00 5c 00 6c 00 66 00 6f 00 2e 00 62 00 61 00 74 00 00 00 00 00 b0 04 02 00 ff ff ff ff 02 00 00 00 3a 00 31 00 00 00 00 00 b0 04 02 00 ff ff ff ff 04 00 00 00 22 00 25 00 73 00 22 00 00 00 00 00 b0 04 02 00 ff ff ff ff 0a 00 00 00 45 00 72 00 61 00 73 00 65 00 20 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}