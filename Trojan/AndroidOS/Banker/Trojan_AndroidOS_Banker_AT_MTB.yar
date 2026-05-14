
rule Trojan_AndroidOS_Banker_AT_MTB{
	meta:
		description = "Trojan:AndroidOS/Banker.AT!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {4c 65 6c 65 6e 74 72 61 2f 6b 75 6d 61 6b 2f 6d 79 66 69 6c 65 2f 4d 61 69 6e 41 63 74 69 76 69 74 79 } //1 Lelentra/kumak/myfile/MainActivity
		$a_01_1 = {0a 02 52 03 6c 03 91 03 02 03 6e 10 ed 05 00 00 0a 04 54 05 5b 03 54 06 5c 03 15 07 00 3f 12 08 15 09 80 40 3d 03 23 00 71 10 24 00 05 00 0a 0a 2d 0a 0a 08 38 0a 1b 00 7b 38 82 88 c8 98 82 4a c9 a8 7b 44 82 44 c9 94 71 30 0c 00 85 07 0a 07 c8 47 } //1
		$a_01_2 = {b0 04 0f 04 6e 10 f6 05 04 00 0c 00 1f 00 0c 07 54 31 7c 03 1f 01 0a 07 6e 10 47 24 01 00 6e 10 f6 05 04 00 0c 01 1f 01 0c 07 54 11 94 10 6e 10 ff 05 04 00 0a 04 52 12 64 00 b0 24 52 11 65 00 b0 14 52 01 a2 00 b0 14 52 00 a3 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}