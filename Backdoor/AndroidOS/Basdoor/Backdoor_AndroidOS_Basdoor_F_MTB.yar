
rule Backdoor_AndroidOS_Basdoor_F_MTB{
	meta:
		description = "Backdoor:AndroidOS/Basdoor.F!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {72 10 33 76 01 00 0a 02 38 02 39 00 72 10 34 76 01 00 0c 02 1f 02 b3 14 38 02 f4 ff 54 73 00 00 22 04 b5 14 70 10 98 73 04 00 54 75 00 00 71 10 09 00 05 00 0c 05 6e 20 a4 73 54 00 6e 20 a4 73 04 00 6e 20 a4 73 24 00 6e 10 b6 73 04 00 0c 04 71 20 0a 00 43 00 54 73 00 00 } //1
		$a_01_1 = {6e 20 a4 73 08 00 71 10 ce 75 07 00 0c 07 6e 20 a4 73 78 00 1a 07 4b 06 6e 20 a4 73 78 00 6e 10 b6 73 08 00 0c 07 70 20 a7 72 76 00 27 06 72 10 c1 76 00 00 0a 02 3d 02 07 00 21 73 b1 23 23 33 ae 1b } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}