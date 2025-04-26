
rule Trojan_Win64_IcedID_MAN_MTB{
	meta:
		description = "Trojan:Win64/IcedID.MAN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {69 6a 6e 69 75 61 73 68 64 79 67 75 61 73 } //1 ijniuashdyguas
		$a_01_1 = {41 49 61 71 64 68 6a 5a 70 70 } //1 AIaqdhjZpp
		$a_01_2 = {45 78 71 45 30 6d 57 } //1 ExqE0mW
		$a_01_3 = {4d 35 34 62 35 72 6e 69 } //1 M54b5rni
		$a_01_4 = {55 4f 76 55 35 6c 76 } //1 UOvU5lv
		$a_01_5 = {57 37 4e 65 73 73 6f 79 41 37 } //1 W7NessoyA7
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}