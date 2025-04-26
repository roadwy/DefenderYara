
rule TrojanDownloader_Win32_Banload_ZDQ{
	meta:
		description = "TrojanDownloader:Win32/Banload.ZDQ,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {41 42 52 41 20 20 45 4d 20 4f 55 54 52 4f 20 43 4f 4d 50 55 54 41 44 4f 52 21 21 00 } //2 䉁䅒†䵅传呕佒䌠䵏啐䅔佄⅒!
		$a_03_1 = {43 3a 5c 41 72 71 75 69 76 6f 73 20 64 65 20 70 72 6f 67 72 61 6d 61 73 5c 41 72 71 75 69 76 6f 73 20 63 6f 6d 75 6e 73 5c 2d (2e 2e|2e) 65 78 65 } //2
		$a_01_2 = {2f 31 31 31 31 2e 6a 70 67 00 } //1 ㄯㄱ⸱灪g
		$a_01_3 = {4b 65 6c 62 65 72 71 75 65 } //1 Kelberque
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}