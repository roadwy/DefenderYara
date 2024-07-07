
rule TrojanDownloader_AndroidOS_Lezok_A{
	meta:
		description = "TrojanDownloader:AndroidOS/Lezok.A,SIGNATURE_TYPE_DEXHSTR_EXT,0c 00 0c 00 06 00 00 "
		
	strings :
		$a_01_0 = {41 70 4d 61 69 6e 2e 62 69 6e } //2 ApMain.bin
		$a_01_1 = {67 65 74 41 73 73 65 74 73 43 6f 72 65 43 6f 64 65 } //2 getAssetsCoreCode
		$a_01_2 = {63 6f 6e 76 65 72 74 55 72 6c 54 6f 4c 6f 63 61 6c 46 69 6c 65 } //2 convertUrlToLocalFile
		$a_01_3 = {66 6f 72 6d 61 74 48 65 78 4d 61 63 54 6f 44 69 67 69 74 73 } //2 formatHexMacToDigits
		$a_01_4 = {77 72 69 74 65 52 65 6d 6f 74 65 44 61 74 61 54 6f 41 70 70 64 61 74 61 } //2 writeRemoteDataToAppdata
		$a_01_5 = {63 68 65 63 6b 43 6f 72 65 43 6f 64 65 28 29 20 64 6f 77 6e 6c 6f 61 64 20 3a 20 } //2 checkCoreCode() download : 
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2) >=12
 
}