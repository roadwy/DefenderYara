
rule TrojanDownloader_BAT_Seraph_MR_MTB{
	meta:
		description = "TrojanDownloader:BAT/Seraph.MR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 06 00 00 "
		
	strings :
		$a_02_0 = {06 09 06 6f 90 02 04 1e 5b 6f 90 02 04 6f 90 02 04 06 09 06 6f 90 02 04 1e 5b 6f 90 02 04 6f 90 02 04 06 17 6f 90 02 04 07 06 6f 90 02 04 17 90 00 } //6
		$a_81_1 = {67 65 74 5f 4b 65 79 53 69 7a 65 } //1 get_KeySize
		$a_81_2 = {73 65 74 5f 49 56 } //1 set_IV
		$a_81_3 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_81_4 = {67 65 74 5f 55 54 46 38 } //1 get_UTF8
		$a_81_5 = {73 65 74 5f 42 6c 6f 63 6b 53 69 7a 65 } //1 set_BlockSize
	condition:
		((#a_02_0  & 1)*6+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=9
 
}