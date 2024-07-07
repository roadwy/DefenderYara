
rule Backdoor_BAT_Crysan_ABD_MTB{
	meta:
		description = "Backdoor:BAT/Crysan.ABD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 06 00 00 "
		
	strings :
		$a_01_0 = {57 94 02 3c 49 02 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 28 00 00 00 0c 00 00 00 2b 00 00 00 70 00 00 00 3f 00 00 00 } //5
		$a_01_1 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d } //1 MemoryStream
		$a_01_2 = {44 65 63 6f 64 65 44 69 72 65 63 74 42 69 74 73 } //1 DecodeDirectBits
		$a_01_3 = {67 65 74 5f 49 73 41 74 74 61 63 68 65 64 } //1 get_IsAttached
		$a_01_4 = {49 73 4c 6f 67 67 69 6e 67 } //1 IsLogging
		$a_01_5 = {43 6f 6e 66 75 73 65 72 45 78 } //1 ConfuserEx
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=10
 
}