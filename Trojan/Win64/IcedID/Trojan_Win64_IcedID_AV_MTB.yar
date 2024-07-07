
rule Trojan_Win64_IcedID_AV_MTB{
	meta:
		description = "Trojan:Win64/IcedID.AV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {79 67 61 67 6b 61 73 6a 66 68 75 61 73 68 66 6a 6b 61 73 6a 61 73 68 } //1 ygagkasjfhuashfjkasjash
		$a_01_1 = {47 44 35 62 4e 31 4d 4b 30 4c 68 } //1 GD5bN1MK0Lh
		$a_01_2 = {56 59 75 6d 78 4b 62 73 33 } //1 VYumxKbs3
		$a_01_3 = {57 70 32 43 62 58 41 53 4d 4d } //1 Wp2CbXASMM
		$a_01_4 = {57 73 31 72 44 67 46 37 57 75 } //1 Ws1rDgF7Wu
		$a_01_5 = {63 4c 51 6a 54 76 39 4b 39 57 39 } //1 cLQjTv9K9W9
		$a_01_6 = {66 75 49 33 4c 52 5a 33 30 71 7a } //1 fuI3LRZ30qz
		$a_01_7 = {67 4c 74 54 75 69 59 33 54 54 } //1 gLtTuiY3TT
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}