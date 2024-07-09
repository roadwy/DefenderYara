
rule TrojanDownloader_Win32_Cutwail_CE{
	meta:
		description = "TrojanDownloader:Win32/Cutwail.CE,SIGNATURE_TYPE_PEHSTR_EXT,20 00 20 00 05 00 00 "
		
	strings :
		$a_01_0 = {81 c6 ca 00 00 00 } //10
		$a_03_1 = {89 85 9c fe ff ff b9 (80 1e 00 00|00 1f 00 00) } //10
		$a_01_2 = {89 07 47 47 47 47 e2 } //10
		$a_00_3 = {4c 6f 61 64 49 6d 61 67 65 57 } //1 LoadImageW
		$a_00_4 = {47 65 74 4f 62 6a 65 63 74 41 } //1 GetObjectA
	condition:
		((#a_01_0  & 1)*10+(#a_03_1  & 1)*10+(#a_01_2  & 1)*10+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=32
 
}