
rule Trojan_Win32_Zusy_LRB_MTB{
	meta:
		description = "Trojan:Win32/Zusy.LRB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 05 00 00 "
		
	strings :
		$a_01_0 = {8a 0c 30 80 e9 42 32 ca 88 0c 30 40 3b c7 } //10
		$a_81_1 = {68 74 74 70 3a 2f 2f 2f 2f 61 2e 64 65 6c 74 61 68 65 61 76 79 2e 72 75 2f 2f 61 } //1 http:////a.deltaheavy.ru//a
		$a_81_2 = {57 6f 72 6d 36 35 2e 44 4c 4c 2e 64 6c 6c } //2 Worm65.DLL.dll
		$a_81_3 = {57 4f 52 4d 36 34 40 40 59 41 58 58 5a } //3 WORM64@@YAXXZ
		$a_81_4 = {57 4f 52 4d 33 32 } //4 WORM32
	condition:
		((#a_01_0  & 1)*10+(#a_81_1  & 1)*1+(#a_81_2  & 1)*2+(#a_81_3  & 1)*3+(#a_81_4  & 1)*4) >=20
 
}