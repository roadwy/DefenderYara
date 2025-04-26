
rule TrojanDropper_AndroidOS_SAgnt_A_xp{
	meta:
		description = "TrojanDropper:AndroidOS/SAgnt.A!xp,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {52 61 77 49 6e 70 75 74 46 69 6c 65 45 } //1 RawInputFileE
		$a_01_1 = {63 68 65 63 6b 41 70 6b 49 74 65 6d 52 4b 37 41 70 6b 49 74 65 6d } //1 checkApkItemRK7ApkItem
		$a_01_2 = {73 74 72 69 6e 67 73 74 75 66 66 31 31 75 6e 70 61 63 6b 41 72 72 61 79 45 69 50 74 6d } //1 stringstuff11unpackArrayEiPtm
		$a_01_3 = {6a 6e 69 75 74 69 6c 73 3a 3a 67 65 74 41 70 70 52 6f 6f 74 44 69 72 28 25 70 2c 20 25 70 29 } //1 jniutils::getAppRootDir(%p, %p)
		$a_01_4 = {67 65 74 4a 61 76 61 43 61 6c 6c 65 72 28 25 70 29 } //1 getJavaCaller(%p)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}