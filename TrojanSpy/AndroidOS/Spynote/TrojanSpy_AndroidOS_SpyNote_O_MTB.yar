
rule TrojanSpy_AndroidOS_SpyNote_O_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SpyNote.O!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {2f 43 6f 6e 66 69 67 2f 73 79 73 2f 61 70 70 73 2f 6c 6f 67 } //1 /Config/sys/apps/log
		$a_01_1 = {5f 63 61 6c 6c 72 5f 6c 73 6e 72 5f } //1 _callr_lsnr_
		$a_01_2 = {47 65 74 52 65 71 75 69 65 72 64 50 72 69 6d 73 } //1 GetRequierdPrims
		$a_03_3 = {22 0e c8 0e 07 e2 76 0a ee 3c 02 00 71 10 ?? 3d 0e 00 0c 0e 5b de e9 30 54 d0 d7 30 22 02 ef 04 70 30 2d 1d e2 00 71 10 ?? 3d 02 00 54 de d7 30 54 d0 d9 30 22 02 ef 04 70 40 2e 1d e2 10 71 10 ?? 3d 02 00 0c 0e 5b de ea 30 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}