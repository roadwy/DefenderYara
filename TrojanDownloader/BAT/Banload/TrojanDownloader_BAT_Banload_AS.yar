
rule TrojanDownloader_BAT_Banload_AS{
	meta:
		description = "TrojanDownloader:BAT/Banload.AS,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 05 00 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 33 6c 6f 61 64 5c } //1 C:\3load\
		$a_01_1 = {43 3a 5c 32 6c 6f 61 64 5c } //1 C:\2load\
		$a_01_2 = {65 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 20 00 43 00 3a 00 5c 00 } //1 explorer C:\
		$a_03_3 = {73 36 00 00 0a 80 0a 00 00 04 72 c5 00 00 70 72 ?? 01 00 70 28 ?? 00 00 06 80 ?? 00 00 04 72 ?? 01 00 70 72 ?? 01 00 70 28 ?? 00 00 06 80 ?? 00 00 04 73 37 00 00 0a 80 ?? 00 00 04 2a } //10
		$a_03_4 = {1f 20 8d 39 00 00 01 13 ?? ?? 28 3a 00 00 0a 03 6f 3b 00 00 0a 6f 3c 00 00 0a 13 ?? 11 ?? 16 11 ?? 16 1f 10 28 3d 00 00 0a } //10
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*10+(#a_03_4  & 1)*10) >=21
 
}