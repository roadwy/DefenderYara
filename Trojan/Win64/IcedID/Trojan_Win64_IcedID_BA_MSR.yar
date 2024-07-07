
rule Trojan_Win64_IcedID_BA_MSR{
	meta:
		description = "Trojan:Win64/IcedID.BA!MSR,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 0a 00 00 "
		
	strings :
		$a_01_0 = {44 4a 42 76 51 65 30 50 61 } //2 DJBvQe0Pa
		$a_01_1 = {49 41 56 66 54 4d 6a 4f 76 } //2 IAVfTMjOv
		$a_01_2 = {49 58 5a 53 4c 42 5a 61 74 30 } //2 IXZSLBZat0
		$a_01_3 = {4a 67 6c 6f 4b 44 7a 67 65 } //2 JgloKDzge
		$a_01_4 = {4a 78 72 74 6b 49 54 6f 6d 70 } //2 JxrtkITomp
		$a_01_5 = {50 75 32 5a 45 62 48 54 75 66 } //2 Pu2ZEbHTuf
		$a_01_6 = {55 72 32 30 34 7a 4a 41 32 } //2 Ur204zJA2
		$a_01_7 = {59 78 6e 39 4b 68 } //2 Yxn9Kh
		$a_01_8 = {67 75 71 55 69 64 51 43 } //2 guqUidQC
		$a_01_9 = {67 79 75 61 73 68 66 68 79 75 67 61 73 } //2 gyuashfhyugas
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2+(#a_01_6  & 1)*2+(#a_01_7  & 1)*2+(#a_01_8  & 1)*2+(#a_01_9  & 1)*2) >=20
 
}