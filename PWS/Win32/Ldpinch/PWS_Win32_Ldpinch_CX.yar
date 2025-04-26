
rule PWS_Win32_Ldpinch_CX{
	meta:
		description = "PWS:Win32/Ldpinch.CX,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 0a 00 00 "
		
	strings :
		$a_01_0 = {2e 2d 68 65 2d 6f 2d 72 75 2e 63 2d 6f 2d 6d } //10 .-he-o-ru.c-o-m
		$a_01_1 = {2a 31 36 33 2a 2e 74 78 74 } //1 *163*.txt
		$a_01_2 = {2a 61 6c 69 6d 61 6d 61 2a 2e 74 78 74 } //1 *alimama*.txt
		$a_01_3 = {2a 61 6c 69 75 6e 69 6f 6e 2a 2e 74 78 74 } //1 *aliunion*.txt
		$a_01_4 = {2a 62 61 69 64 75 2a 2e 74 78 74 } //1 *baidu*.txt
		$a_01_5 = {2a 67 6f 6f 67 6c 65 2a 2e 74 78 74 } //1 *google*.txt
		$a_01_6 = {2a 73 69 6e 61 2a 2e 74 78 74 } //1 *sina*.txt
		$a_01_7 = {2a 73 6f 67 6f 75 2a 2e 74 78 74 } //1 *sogou*.txt
		$a_01_8 = {2a 73 6f 68 75 2a 2e 74 78 74 } //1 *sohu*.txt
		$a_01_9 = {2a 79 61 68 6f 6f 2a 2e 74 78 74 } //1 *yahoo*.txt
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=13
 
}