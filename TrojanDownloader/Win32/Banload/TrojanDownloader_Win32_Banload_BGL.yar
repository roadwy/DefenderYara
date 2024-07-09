
rule TrojanDownloader_Win32_Banload_BGL{
	meta:
		description = "TrojanDownloader:Win32/Banload.BGL,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 06 00 00 "
		
	strings :
		$a_01_0 = {42 00 41 00 4b 00 41 00 2e 00 42 00 41 00 4b 00 } //1 BAKA.BAK
		$a_01_1 = {42 00 55 00 4a 00 55 00 2e 00 42 00 41 00 4b 00 } //1 BUJU.BAK
		$a_01_2 = {70 00 6b 00 62 00 61 00 63 00 6b 00 23 00 } //1 pkback#
		$a_01_3 = {2e 00 67 00 6f 00 6f 00 67 00 6c 00 65 00 61 00 70 00 69 00 73 00 2e 00 63 00 6f 00 6d 00 2f 00 } //1 .googleapis.com/
		$a_01_4 = {28 00 42 00 72 00 61 00 73 00 69 00 6c 00 29 00 } //1 (Brasil)
		$a_03_5 = {8b 45 94 50 8d 45 8c ba ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 45 8c 5a e8 ?? ?? ?? ?? 85 c0 7e 05 83 cb ff eb 02 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_03_5  & 1)*1) >=4
 
}