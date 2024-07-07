
rule Trojan_AndroidOS_SpyBanker_C_MTB{
	meta:
		description = "Trojan:AndroidOS/SpyBanker.C!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {72 75 2f 74 68 65 66 74 2f 68 79 70 6f 74 68 65 73 69 7a 65 } //1 ru/theft/hypothesize
		$a_01_1 = {41 67 65 6e 63 79 4f 66 66 69 63 69 61 6c } //1 AgencyOfficial
		$a_01_2 = {49 42 79 73 75 } //1 IBysu
		$a_01_3 = {71 75 6f 73 74 70 65 6f 70 6c 73 } //1 quostpeopls
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}