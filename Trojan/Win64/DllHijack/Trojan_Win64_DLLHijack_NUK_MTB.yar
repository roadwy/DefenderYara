
rule Trojan_Win64_DLLHijack_NUK_MTB{
	meta:
		description = "Trojan:Win64/DLLHijack.NUK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 08 00 00 "
		
	strings :
		$a_81_0 = {34 69 32 58 72 6e 4b 56 51 79 33 64 6e 35 5a 76 66 5a 4f 63 57 39 52 48 61 51 45 } //1 4i2XrnKVQy3dn5ZvfZOcW9RHaQE
		$a_81_1 = {39 4b 38 58 52 73 43 76 52 33 6d 62 35 39 46 56 35 46 34 59 67 66 } //1 9K8XRsCvR3mb59FV5F4Ygf
		$a_81_2 = {47 57 46 53 6f 38 47 59 74 38 78 6a 67 71 50 62 32 39 4c 68 51 32 31 79 68 } //1 GWFSo8GYt8xjgqPb29LhQ21yh
		$a_81_3 = {6a 4d 39 36 31 7a 65 75 34 45 4b 73 38 65 44 6f 33 4a 6e 6e 56 32 58 67 33 6d 35 4e } //1 jM961zeu4EKs8eDo3JnnV2Xg3m5N
		$a_81_4 = {39 58 4e 35 50 6b 66 76 68 32 33 69 73 78 6d 4c 45 53 34 } //2 9XN5Pkfvh23isxmLES4
		$a_81_5 = {32 33 34 34 75 4f 46 35 37 37 38 4b 75 34 6c 62 31 62 35 68 5a 6c 34 6d 45 } //1 2344uOF5778Ku4lb1b5hZl4mE
		$a_81_6 = {45 6e 63 72 79 70 74 65 64 } //1 Encrypted
		$a_81_7 = {4b 31 58 61 36 75 53 68 4f 79 66 61 6f 50 46 36 58 44 31 4d 53 56 53 74 35 74 55 35 } //1 K1Xa6uShOyfaoPF6XD1MSVSt5tU5
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*2+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=9
 
}