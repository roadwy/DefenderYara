
rule Trojan_AndroidOS_SpyBanker_NM{
	meta:
		description = "Trojan:AndroidOS/SpyBanker.NM,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {75 70 6c 6f 61 64 49 6d 61 67 65 73 41 6e 64 54 68 65 6e 44 61 74 61 } //2 uploadImagesAndThenData
		$a_01_1 = {67 65 74 49 6d 72 61 6e 50 61 74 68 } //2 getImranPath
		$a_01_2 = {4c 6f 61 6e 53 75 63 65 73 73 66 75 6c 6c 79 } //2 LoanSucessfully
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}