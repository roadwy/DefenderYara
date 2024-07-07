
rule TrojanDownloader_Win32_Banload_QP{
	meta:
		description = "TrojanDownloader:Win32/Banload.QP,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {2f 66 69 6c 65 2e 61 73 70 78 3f 66 69 6c 65 3d 31 26 67 65 6e 3d 31 00 } //1
		$a_03_1 = {8b 40 0c 8b 00 8b 00 89 85 90 01 04 6a 06 6a 01 6a 02 e8 90 01 04 89 45 ec 6a 10 8d 85 90 01 04 50 8b 45 ec 50 e8 90 01 04 40 0f 84 90 00 } //1
		$a_03_2 = {68 01 04 00 00 8d 85 90 01 04 50 8b 45 ec 50 e8 90 01 04 89 45 dc 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}