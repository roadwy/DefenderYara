
rule TrojanSpy_AndroidOS_Ahmyth_K_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Ahmyth.K!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {66 69 6c 65 6d 61 6e 61 67 65 72 2f 73 65 61 72 63 68 2f 6f 74 68 2f 64 69 72 2f 4d 61 69 6e 41 63 74 69 76 69 74 79 } //1 filemanager/search/oth/dir/MainActivity
		$a_03_1 = {01 40 01 71 20 ?? 07 04 00 6e 10 ?? 01 05 00 0c 01 1a 02 ?? 15 6e 20 ?? 19 12 00 0a 01 38 01 05 00 71 10 ?? 15 04 00 0e 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}