
rule TrojanDropper_AndroidOS_Banker_AJ_MTB{
	meta:
		description = "TrojanDropper:AndroidOS/Banker.AJ!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {35 21 2f 00 14 04 3b a7 00 00 b0 46 48 04 03 01 d9 08 06 1f dc 09 01 03 48 09 07 09 da 0a 08 4e 91 0a 06 0a b1 86 b0 a6 da 06 06 00 b0 46 93 04 0a 0a db 04 04 01 df 04 04 01 b0 46 94 04 0a 0a b0 46 97 04 06 09 8d 44 4f 04 05 01 14 04 59 8a 7b 00 93 04 0a 04 d8 01 01 01 01 a6 28 d2 } //1
		$a_00_1 = {64 61 6c 76 69 6b 2f 73 79 73 74 65 6d 2f 44 65 78 43 6c 61 73 73 4c 6f 61 64 65 72 3b } //1 dalvik/system/DexClassLoader;
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}