
rule Trojan_Win32_Copak_BE_MTB{
	meta:
		description = "Trojan:Win32/Copak.BE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {31 32 29 c8 41 81 c2 04 00 00 00 01 c9 41 39 da 75 e9 } //3
		$a_01_1 = {31 1e 40 81 c6 04 00 00 00 09 c0 21 f8 39 ce 75 ea } //3
		$a_01_2 = {8b 0c 24 83 c4 04 42 21 ff b9 67 73 cd 7e 81 fa 29 ed 00 01 75 c3 } //2
		$a_01_3 = {01 c1 81 c7 01 00 00 00 81 c1 b4 65 11 c1 49 81 ff 38 46 00 01 75 bc } //2
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=5
 
}