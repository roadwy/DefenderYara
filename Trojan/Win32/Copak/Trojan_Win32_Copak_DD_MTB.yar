
rule Trojan_Win32_Copak_DD_MTB{
	meta:
		description = "Trojan:Win32/Copak.DD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {81 c1 b3 77 48 c0 31 3a 51 5b 81 eb 6b 35 16 0e 42 39 f2 75 } //2
		$a_01_1 = {81 c2 ff b0 17 38 31 0f 01 d2 47 39 f7 75 } //2
		$a_01_2 = {81 eb a1 f8 7d 3c 81 c3 4e be 5f ff 42 81 c7 83 c1 0b 94 81 fa 4c ac 00 01 75 } //3
		$a_01_3 = {21 c0 81 e8 a3 be 3d 59 47 89 c0 81 ff 93 6a 00 01 75 } //3
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*3+(#a_01_3  & 1)*3) >=5
 
}