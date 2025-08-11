
rule Trojan_Win32_PoolInject_MR_MTB{
	meta:
		description = "Trojan:Win32/PoolInject.MR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 07 00 00 "
		
	strings :
		$a_81_0 = {53 74 6f 70 20 72 65 76 65 72 73 69 6e 67 20 74 68 65 20 62 69 6e 61 72 79 } //1 Stop reversing the binary
		$a_81_1 = {52 65 63 6f 6e 73 69 64 65 72 20 79 6f 75 72 20 6c 69 66 65 20 63 68 6f 69 63 65 73 } //1 Reconsider your life choices
		$a_81_2 = {41 6e 64 20 67 6f 20 74 6f 75 63 68 20 73 6f 6d 65 20 67 72 61 73 73 } //1 And go touch some grass
		$a_81_3 = {46 61 69 6c 20 74 6f 20 73 63 68 65 64 75 6c 65 20 74 68 65 20 63 68 6f 72 65 21 } //1 Fail to schedule the chore!
		$a_81_4 = {66 75 74 75 72 65 20 61 6c 72 65 61 64 79 20 72 65 74 72 69 65 76 65 64 } //1 future already retrieved
		$a_81_5 = {70 72 6f 6d 69 73 65 20 61 6c 72 65 61 64 79 20 73 61 74 69 73 66 69 65 64 } //1 promise already satisfied
		$a_01_6 = {41 ba 40 00 00 00 41 8b c8 48 8b d0 83 e1 3f 44 2b d1 41 0f b6 ca 48 d3 ca 49 33 d0 } //2
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_01_6  & 1)*2) >=8
 
}