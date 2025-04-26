
rule TrojanSpy_AndroidOS_Banker_AG_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Banker.AG!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 07 00 00 "
		
	strings :
		$a_01_0 = {6e 69 6f 75 68 70 6b 61 65 66 62 7a 2f 71 6b 77 65 68 69 78 71 71 6f 6f 74 6d 6f 71 68 68 62 6a 68 } //1 niouhpkaefbz/qkwehixqqootmoqhhbjh
		$a_01_1 = {6e 61 69 65 62 72 76 6c 2f 65 6f 6a 69 75 73 6f 6b 68 66 6c 62 } //1 naiebrvl/eojiusokhflb
		$a_01_2 = {76 63 6f 6a 71 62 66 62 76 6d 76 77 65 2f 6a 64 6e 6d 6a 71 6c 6c 6d } //1 vcojqbfbvmvwe/jdnmjqllm
		$a_01_3 = {62 6b 68 72 77 65 66 65 74 6e 62 7a 76 78 67 6e 2f 72 78 6d 65 64 79 68 6f 71 6f 78 } //1 bkhrwefetnbzvxgn/rxmedyhoqox
		$a_01_4 = {2f 64 65 76 2f 63 70 75 63 74 6c 2f 74 61 73 6b 73 } //1 /dev/cpuctl/tasks
		$a_01_5 = {6f 6e 54 61 73 6b 52 65 6d 6f 76 65 64 } //1 onTaskRemoved
		$a_01_6 = {69 73 41 64 6d 69 6e 41 63 74 69 76 65 } //1 isAdminActive
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=4
 
}