
rule TrojanDownloader_AndroidOS_FireHelper_A{
	meta:
		description = "TrojanDownloader:AndroidOS/FireHelper.A,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_00_0 = {12 00 21 21 35 10 0c 00 48 01 02 00 df 01 01 37 8d 11 4f 01 02 00 d8 00 00 01 28 f4 } //1
		$a_00_1 = {66 69 72 65 68 65 6c 70 65 72 2e 6a 61 72 } //1 firehelper.jar
		$a_00_2 = {66 69 72 65 68 65 6c 70 65 72 2e 64 65 78 } //1 firehelper.dex
		$a_01_3 = {5a 47 46 73 64 6d 6c 72 4c 6e 4e 35 63 33 52 6c 62 53 35 45 5a 58 68 44 62 47 46 7a 63 30 78 76 59 57 52 6c 63 67 3d 3d } //1 ZGFsdmlrLnN5c3RlbS5EZXhDbGFzc0xvYWRlcg==
		$a_00_4 = {63 6f 2e 6c 2e 6d } //1 co.l.m
		$a_00_5 = {46 49 52 45 59 4d 4e 5f 32 } //1 FIREYMN_2
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_01_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=5
 
}