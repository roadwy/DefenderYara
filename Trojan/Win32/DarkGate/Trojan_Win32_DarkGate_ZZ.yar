
rule Trojan_Win32_DarkGate_ZZ{
	meta:
		description = "Trojan:Win32/DarkGate.ZZ,SIGNATURE_TYPE_PEHSTR_EXT,fffffff1 00 fffffff1 00 07 00 00 "
		
	strings :
		$a_01_0 = {f1 d5 00 fa 4c 62 cc f4 0f 0b } //1
		$a_03_1 = {80 e1 3f c1 e1 02 8a 5d ?? 80 e3 30 81 e3 ff 00 00 00 c1 eb 04 02 cb } //100
		$a_03_2 = {80 e1 0f c1 e1 04 8a 5d ?? 80 e3 3c 81 e3 ff 00 00 00 c1 eb 02 02 cb } //100
		$a_81_3 = {5f 5f 5f 5f 70 61 64 6f 72 75 5f 5f 5f 5f } //10 ____padoru____
		$a_81_4 = {45 72 72 6f 72 3a 20 6e 6f 20 64 65 6c 69 6d 69 74 61 64 6f 72 20 6d 6f 6e 69 74 6f 72 } //10 Error: no delimitador monitor
		$a_81_5 = {68 76 6e 63 20 65 72 72 6f 72 } //10 hvnc error
		$a_81_6 = {2d 61 63 63 65 70 74 65 75 6c 61 20 2d 64 20 2d 75 20 } //10 -accepteula -d -u 
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*100+(#a_03_2  & 1)*100+(#a_81_3  & 1)*10+(#a_81_4  & 1)*10+(#a_81_5  & 1)*10+(#a_81_6  & 1)*10) >=241
 
}