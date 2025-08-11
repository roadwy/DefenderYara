
rule Trojan_Win64_PoolInject_MR_MTB{
	meta:
		description = "Trojan:Win64/PoolInject.MR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 "
		
	strings :
		$a_01_0 = {41 8b c3 48 c1 e9 10 25 ff 00 04 00 83 e1 06 89 05 6d 34 11 00 48 81 c9 29 00 00 01 48 f7 d1 48 23 0d 10 1d 11 00 } //10
		$a_81_1 = {53 74 6f 70 20 72 65 76 65 72 73 69 6e 67 20 74 68 65 20 62 69 6e 61 72 79 } //1 Stop reversing the binary
		$a_81_2 = {52 65 63 6f 6e 73 69 64 65 72 20 79 6f 75 72 20 6c 69 66 65 20 63 68 6f 69 63 65 73 } //1 Reconsider your life choices
		$a_81_3 = {41 6e 64 20 67 6f 20 74 6f 75 63 68 20 73 6f 6d 65 20 67 72 61 73 73 } //1 And go touch some grass
	condition:
		((#a_01_0  & 1)*10+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=13
 
}