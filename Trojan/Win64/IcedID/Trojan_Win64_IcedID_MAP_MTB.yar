
rule Trojan_Win64_IcedID_MAP_MTB{
	meta:
		description = "Trojan:Win64/IcedID.MAP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {34 6b 6a 30 39 65 2e 64 6c 6c } //1 4kj09e.dll
		$a_01_1 = {48 61 66 62 68 6a 73 61 66 76 68 73 61 64 62 79 73 61 } //1 Hafbhjsafvhsadbysa
		$a_01_2 = {42 44 35 71 45 36 6e 78 48 44 78 } //1 BD5qE6nxHDx
		$a_01_3 = {53 70 53 4e 6d 5a 39 54 65 4e } //1 SpSNmZ9TeN
		$a_01_4 = {65 57 44 51 59 78 6d 47 4c 71 66 } //1 eWDQYxmGLqf
		$a_01_5 = {65 6b 6a 76 68 33 75 6d 71 63 38 4b 50 30 } //1 ekjvh3umqc8KP0
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}
rule Trojan_Win64_IcedID_MAP_MTB_2{
	meta:
		description = "Trojan:Win64/IcedID.MAP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 06 00 00 "
		
	strings :
		$a_01_0 = {81 84 24 84 01 00 00 f1 00 00 00 c7 84 24 88 01 00 00 53 01 00 00 66 3b c0 74 18 83 84 24 7c 01 00 00 1b c7 84 24 80 01 00 00 03 00 00 00 66 3b c0 74 46 } //1
		$a_01_1 = {83 84 24 38 01 00 00 2a c7 84 24 3c 01 00 00 1d 01 00 00 3a ed 0f 84 21 ff ff ff 83 84 24 cc 00 00 00 03 c7 84 24 d0 00 00 00 0b 00 00 00 3a c9 0f 84 a1 00 00 00 } //1
		$a_01_2 = {83 84 24 18 02 00 00 14 c7 84 24 1c 02 00 00 29 09 00 00 66 3b c9 74 15 83 84 24 20 02 00 00 3d c7 44 24 30 f3 00 00 00 66 3b ed 74 54 } //1
		$a_01_3 = {83 84 24 a4 00 00 00 6a c7 84 24 a8 00 00 00 0d 01 00 00 3a c9 74 00 83 84 24 a8 00 00 00 4d c7 84 24 ac 00 00 00 a7 00 00 00 66 3b ff 74 34 } //1
		$a_01_4 = {79 73 62 61 68 66 62 68 61 79 67 75 73 66 68 6a 61 73 6b 66 62 68 } //1 ysbahfbhaygusfhjaskfbh
		$a_01_5 = {79 67 61 67 69 68 73 66 67 79 75 6b 61 73 6a 68 67 79 6a 61 73 } //1 ygagihsfgyukasjhgyjas
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=1
 
}