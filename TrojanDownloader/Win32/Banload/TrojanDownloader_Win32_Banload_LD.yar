
rule TrojanDownloader_Win32_Banload_LD{
	meta:
		description = "TrojanDownloader:Win32/Banload.LD,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {66 33 c0 8a c3 66 05 e7 00 0f 80 90 01 04 0f bf c8 81 f9 ff 00 00 00 7e 0c 81 e9 ff 00 00 00 0f 80 90 00 } //1
		$a_01_1 = {ff 91 f8 06 00 00 89 85 d8 fd ff ff 83 bd d8 fd ff ff 00 7d 23 68 f8 06 00 00 } //1
		$a_01_2 = {5a 75 63 61 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}