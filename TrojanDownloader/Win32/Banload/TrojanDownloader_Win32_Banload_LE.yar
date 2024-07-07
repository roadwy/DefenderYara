
rule TrojanDownloader_Win32_Banload_LE{
	meta:
		description = "TrojanDownloader:Win32/Banload.LE,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {7c 5f 8b 45 f0 c1 e0 06 03 d8 89 5d f0 83 c7 06 83 ff 08 7c 42 83 ef 08 } //1
		$a_00_1 = {5c 00 74 00 61 00 73 00 6b 00 65 00 78 00 65 00 63 00 2e 00 65 00 78 00 65 00 00 00 } //1
		$a_00_2 = {41 00 74 00 69 00 76 00 61 00 64 00 6f 00 00 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}