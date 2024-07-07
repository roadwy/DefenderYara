
rule TrojanDropper_AndroidOS_Wroba_FA_MTB{
	meta:
		description = "TrojanDropper:AndroidOS/Wroba.FA!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {71 00 0c 00 00 00 0b 00 16 02 f0 55 bb 20 10 00 } //1
		$a_00_1 = {67 65 74 52 75 6e 74 69 6d 65 } //1 getRuntime
		$a_00_2 = {67 65 74 43 6c 61 73 73 4c 6f 61 64 65 72 } //1 getClassLoader
		$a_00_3 = {50 61 74 68 43 6c 61 73 73 4c 6f 61 64 65 72 } //1 PathClassLoader
		$a_00_4 = {66 69 6e 64 4c 69 62 72 61 72 79 } //1 findLibrary
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}