
rule Adware_AndroidOS_Mobidash_AJ_MTB{
	meta:
		description = "Adware:AndroidOS/Mobidash.AJ!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {63 6f 6d 2f 64 65 78 74 72 61 64 65 2f 61 6e 64 72 6f 69 64 2f 4d 61 69 6e 41 63 74 69 76 69 74 79 } //1 com/dextrade/android/MainActivity
		$a_03_1 = {32 04 00 6e 10 ?? 3d 04 00 0c 00 72 10 ?? 55 00 00 0c 00 54 41 ?? 21 38 01 0c 00 22 02 19 00 12 03 70 30 62 00 42 03 6e 30 ?? 9f 10 02 0e 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}