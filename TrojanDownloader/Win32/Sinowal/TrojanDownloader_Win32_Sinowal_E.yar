
rule TrojanDownloader_Win32_Sinowal_E{
	meta:
		description = "TrojanDownloader:Win32/Sinowal.E,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {83 79 58 05 0f 83 } //1
		$a_01_1 = {8b 45 fc 83 c0 01 50 8f 45 fc } //1
		$a_00_2 = {8f 45 f5 50 8f 45 f9 66 89 45 fd 55 2b eb 8b eb 5d 3b f0 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}