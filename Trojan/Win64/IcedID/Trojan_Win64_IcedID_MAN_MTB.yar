
rule Trojan_Win64_IcedID_MAN_MTB{
	meta:
		description = "Trojan:Win64/IcedID.MAN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {69 6a 6e 69 75 61 73 68 64 79 67 75 61 73 } //01 00  ijniuashdyguas
		$a_01_1 = {41 49 61 71 64 68 6a 5a 70 70 } //01 00  AIaqdhjZpp
		$a_01_2 = {45 78 71 45 30 6d 57 } //01 00  ExqE0mW
		$a_01_3 = {4d 35 34 62 35 72 6e 69 } //01 00  M54b5rni
		$a_01_4 = {55 4f 76 55 35 6c 76 } //01 00  UOvU5lv
		$a_01_5 = {57 37 4e 65 73 73 6f 79 41 37 } //00 00  W7NessoyA7
	condition:
		any of ($a_*)
 
}