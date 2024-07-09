
rule TrojanDownloader_BAT_Banload_V{
	meta:
		description = "TrojanDownloader:BAT/Banload.V,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_03_0 = {00 70 0a 06 17 28 (02|05) 00 00 06 0b 07 0c 1f 1a 28 ?? 00 00 0a 0d 09 72 ?? 00 00 70 28 ?? 00 00 0a 13 04 } //1
		$a_03_1 = {43 00 4f 00 4e 00 43 00 4c 00 55 00 49 00 52 00 [0-06] 62 00 75 00 74 00 74 00 6f 00 6e 00 } //1
		$a_03_2 = {46 00 65 00 63 00 68 00 61 00 72 00 [0-06] 74 00 65 00 78 00 74 00 42 00 6f 00 78 00 } //1
		$a_01_3 = {63 3a 5c 55 73 65 72 73 5c 50 52 4f 56 49 44 45 52 5c 44 65 73 6b 74 6f 70 5c 53 4f 50 41 5c 4c 4f 41 44 5f 45 58 45 } //1 c:\Users\PROVIDER\Desktop\SOPA\LOAD_EXE
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}