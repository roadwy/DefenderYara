
rule Trojan_Win32_DarkGate_ZY{
	meta:
		description = "Trojan:Win32/DarkGate.ZY,SIGNATURE_TYPE_PEHSTR_EXT,fffffff1 00 fffffff1 00 07 00 00 "
		
	strings :
		$a_01_0 = {f1 d5 00 fa 4c 62 cc f4 0f 0b } //1
		$a_03_1 = {80 e1 3f c1 e1 02 8a 5d ?? 80 e3 30 81 e3 ff 00 00 00 c1 eb 04 02 cb } //100
		$a_03_2 = {80 e1 0f c1 e1 04 8a 5d ?? 80 e3 3c 81 e3 ff 00 00 00 c1 eb 02 02 cb } //100
		$a_81_3 = {6d 65 69 6d 70 6f 72 74 61 75 6e 61 6d 69 65 72 64 61 73 69 64 65 73 63 69 66 72 61 73 6c 6f 73 6c 6f 67 73 } //10 meimportaunamierdasidescifrasloslogs
		$a_81_4 = {70 75 65 72 74 6f 20 69 73 20 6e 6f 74 20 6e 75 6d 62 65 72 } //10 puerto is not number
		$a_81_5 = {64 65 6c 69 6b 65 79 20 6e 6f 74 20 66 6f 75 6e 64 } //10 delikey not found
		$a_81_6 = {2d 2d 5f 42 69 6e 64 65 72 5f 2d 2d } //10 --_Binder_--
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*100+(#a_03_2  & 1)*100+(#a_81_3  & 1)*10+(#a_81_4  & 1)*10+(#a_81_5  & 1)*10+(#a_81_6  & 1)*10) >=241
 
}