
rule TrojanDownloader_BAT_Remcos_PZJM_MTB{
	meta:
		description = "TrojanDownloader:BAT/Remcos.PZJM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 04 00 00 "
		
	strings :
		$a_02_0 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 31 00 36 00 32 00 2e 00 32 00 33 00 30 00 2e 00 34 00 38 00 2e 00 31 00 38 00 39 00 2f 00 75 00 70 00 6c 00 6f 00 61 00 64 00 73 00 2f 00 [0-0f] 2e 00 65 00 78 00 65 00 } //7
		$a_00_1 = {57 72 69 74 65 41 6c 6c 42 79 74 65 73 } //1 WriteAllBytes
		$a_00_2 = {47 65 74 42 79 74 65 41 72 72 61 79 41 73 79 6e 63 } //1 GetByteArrayAsync
		$a_00_3 = {47 65 74 54 65 6d 70 46 69 6c 65 4e 61 6d 65 } //1 GetTempFileName
	condition:
		((#a_02_0  & 1)*7+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=10
 
}