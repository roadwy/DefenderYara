
rule Trojan_Win64_IcedID_DX_MTB{
	meta:
		description = "Trojan:Win64/IcedID.DX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 0a 00 00 "
		
	strings :
		$a_01_0 = {45 31 4e 44 65 4e 4e 34 6e 66 42 51 32 } //10 E1NDeNN4nfBQ2
		$a_01_1 = {48 67 68 63 67 78 61 73 68 66 67 66 73 66 67 64 66 } //1 Hghcgxashfgfsfgdf
		$a_01_2 = {49 4e 71 76 34 31 4b 47 6d 63 66 36 38 } //1 INqv41KGmcf68
		$a_01_3 = {4c 52 44 79 4b 39 4f 56 78 73 33 79 55 77 } //1 LRDyK9OVxs3yUw
		$a_01_4 = {4d 78 66 4d 52 52 6d 5a 66 56 } //1 MxfMRRmZfV
		$a_01_5 = {42 48 54 65 33 4c 53 33 49 79 72 4d 59 } //10 BHTe3LS3IyrMY
		$a_01_6 = {45 53 58 6f 6c 78 6c 32 41 6f } //1 ESXolxl2Ao
		$a_01_7 = {48 67 6a 68 67 68 78 67 68 67 63 78 68 63 63 78 73 } //1 Hgjhghxghgcxhccxs
		$a_01_8 = {50 46 61 34 4b 61 62 63 45 30 6c 57 33 6a } //1 PFa4KabcE0lW3j
		$a_01_9 = {63 50 6c 56 71 53 64 46 72 75 4f 59 6a 41 77 68 } //1 cPlVqSdFruOYjAwh
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*10+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=14
 
}