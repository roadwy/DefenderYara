
rule TrojanDropper_AndroidOS_SpyAgnt_A_MTB{
	meta:
		description = "TrojanDropper:AndroidOS/SpyAgnt.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {6f 66 38 37 6f 61 75 66 61 6c 64 6a 61 77 64 6a 6b 77 2e 64 65 78 } //01 00  of87oaufaldjawdjkw.dex
		$a_01_1 = {4c 69 62 31 33 72 65 61 64 41 73 73 65 74 46 69 6c 65 45 50 37 5f 4a 4e 49 45 6e 76 } //01 00  Lib13readAssetFileEP7_JNIEnv
		$a_01_2 = {63 61 6c 6c 20 63 69 70 2e 69 6e 69 74 28 43 69 70 68 65 72 2e 44 45 43 52 59 50 54 5f 4d 4f 44 45 2c 20 6d 79 4b 65 79 29 } //01 00  call cip.init(Cipher.DECRYPT_MODE, myKey)
		$a_01_3 = {64 61 6c 76 69 6b 2f 73 79 73 74 65 6d 2f 44 65 78 43 6c 61 73 73 4c 6f 61 64 65 72 } //00 00  dalvik/system/DexClassLoader
	condition:
		any of ($a_*)
 
}