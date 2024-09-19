
rule Trojan_Win32_DarkGate_ZX{
	meta:
		description = "Trojan:Win32/DarkGate.ZX,SIGNATURE_TYPE_PEHSTR_EXT,ffffffdd 00 ffffffdd 00 05 00 00 "
		
	strings :
		$a_01_0 = {f1 d5 00 fa 4c 62 cc f4 0f 0b } //1
		$a_03_1 = {80 e1 3f c1 e1 02 8a 5d ?? 80 e3 30 81 e3 ff 00 00 00 c1 eb 04 02 cb } //100
		$a_03_2 = {80 e1 0f c1 e1 04 8a 5d ?? 80 e3 3c 81 e3 ff 00 00 00 c1 eb 02 02 cb } //100
		$a_81_3 = {2d 2d 5f 42 69 6e 64 65 72 5f 2d 2d } //10 --_Binder_--
		$a_81_4 = {7c 7c 5f 42 69 6e 64 65 72 5f 7c 7c } //10 ||_Binder_||
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*100+(#a_03_2  & 1)*100+(#a_81_3  & 1)*10+(#a_81_4  & 1)*10) >=221
 
}