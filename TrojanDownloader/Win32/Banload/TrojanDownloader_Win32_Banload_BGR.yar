
rule TrojanDownloader_Win32_Banload_BGR{
	meta:
		description = "TrojanDownloader:Win32/Banload.BGR,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 0a 00 00 "
		
	strings :
		$a_01_0 = {70 00 6b 00 62 00 61 00 63 00 6b 00 23 00 } //1 pkback#
		$a_01_1 = {54 48 61 63 6b 4d 65 6d 6f 72 79 53 74 72 65 61 6d 47 } //1 THackMemoryStreamG
		$a_01_2 = {41 00 4c 00 41 00 53 00 43 00 41 00 44 00 4e 00 53 00 } //1 ALASCADNS
		$a_01_3 = {77 00 6f 00 72 00 6b 00 73 00 6e 00 65 00 74 00 } //1 worksnet
		$a_01_4 = {4c 00 4f 00 47 00 53 00 44 00 41 00 52 00 46 00 } //1 LOGSDARF
		$a_01_5 = {53 00 50 00 41 00 52 00 54 00 41 00 4e 00 2e 00 70 00 69 00 67 00 } //10 SPARTAN.pig
		$a_01_6 = {6d 00 61 00 67 00 6f 00 2e 00 70 00 69 00 67 00 } //10 mago.pig
		$a_03_7 = {2e 00 70 00 69 00 67 00 [0-10] 68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 67 00 65 00 74 00 2e 00 61 00 64 00 6f 00 62 00 65 00 } //10
		$a_01_8 = {6c 00 6f 00 76 00 65 00 6d 00 61 00 7a 00 } //10 lovemaz
		$a_03_9 = {ba 05 00 00 00 e8 ?? ?? ?? ff a1 ?? ?? ?? 00 8b 00 e8 ?? ?? ?? ff 33 d2 55 68 ?? ?? ?? 00 64 ff 32 64 89 22 8d 4d ?? ba ?? ?? ?? 00 b8 ?? ?? ?? 00 } //10
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*10+(#a_01_6  & 1)*10+(#a_03_7  & 1)*10+(#a_01_8  & 1)*10+(#a_03_9  & 1)*10) >=20
 
}