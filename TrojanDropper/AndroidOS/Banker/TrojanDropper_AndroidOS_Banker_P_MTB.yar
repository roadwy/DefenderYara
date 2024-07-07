
rule TrojanDropper_AndroidOS_Banker_P_MTB{
	meta:
		description = "TrojanDropper:AndroidOS/Banker.P!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_03_0 = {48 83 ec 38 48 89 d5 48 89 fb 48 8b 07 48 8d 35 90 01 02 ff ff ff 90 90 90 01 02 00 00 49 89 c6 48 8d 35 90 01 02 ff ff 48 89 df 31 d2 48 89 e9 e8 90 01 02 00 00 49 89 c4 48 89 df 31 f6 48 89 ea e8 90 01 02 00 00 48 89 44 24 28 48 8b 03 48 89 df 48 89 ee ff 90 90 90 01 02 00 00 4c 8b 03 48 8d 15 90 01 02 ff ff 48 8d 0d 90 01 02 ff ff 48 89 df 48 89 c6 41 ff 90 00 } //2
		$a_03_1 = {41 89 c6 48 89 df 48 89 ee e8 90 01 02 00 00 48 8d 15 90 01 02 ff ff 48 89 c7 44 89 f6 e8 90 01 02 00 00 48 89 df 4c 89 64 24 30 4c 89 e6 48 89 c2 44 89 f1 e8 90 01 02 00 00 85 c0 90 00 } //1
		$a_00_2 = {6f 70 65 6e 52 61 77 52 65 73 6f 75 72 63 65 } //1 openRawResource
		$a_00_3 = {64 61 6c 76 69 6b 2f 73 79 73 74 65 6d 2f 44 65 78 43 6c 61 73 73 4c 6f 61 64 65 72 } //1 dalvik/system/DexClassLoader
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=5
 
}