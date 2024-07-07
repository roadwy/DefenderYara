
rule TrojanDropper_AndroidOS_Agent_B_MTB{
	meta:
		description = "TrojanDropper:AndroidOS/Agent.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_02_0 = {0d 01 6e 10 90 01 01 00 01 00 6e 10 90 01 01 00 02 00 0c 01 21 12 35 20 13 00 48 02 01 00 d7 22 ff 00 8d 22 4f 02 01 00 d8 00 00 01 28 f4 6e 10 90 01 01 00 05 00 6e 10 90 01 01 00 02 00 28 e9 07 10 28 cd 90 00 } //1
		$a_00_1 = {67 65 74 43 6c 61 73 73 4c 6f 61 64 65 72 } //1 getClassLoader
		$a_00_2 = {6e 61 74 69 76 65 4c 69 62 72 61 72 79 44 69 72 } //1 nativeLibraryDir
		$a_00_3 = {73 65 74 41 63 63 65 73 73 69 62 6c 65 } //1 setAccessible
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}