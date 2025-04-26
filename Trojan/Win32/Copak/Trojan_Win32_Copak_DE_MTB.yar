
rule Trojan_Win32_Copak_DE_MTB{
	meta:
		description = "Trojan:Win32/Copak.DE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {31 16 09 c0 89 c3 46 29 c0 83 ec 04 89 04 24 5b 39 fe 75 db } //2
		$a_01_1 = {09 db 31 01 89 d3 09 db 41 81 eb a9 9d c2 7c 39 f1 75 e1 } //2
		$a_01_2 = {01 d2 81 ea 01 00 00 00 31 30 40 39 d8 75 e7 } //2
		$a_01_3 = {29 fe 43 21 ff 21 f6 4f 81 fb c4 cc 00 01 75 bc } //3
		$a_01_4 = {21 db 81 c6 01 00 00 00 89 de 58 21 f3 42 46 81 fa cf 7b 00 01 75 bf } //3
		$a_01_5 = {29 f0 81 c1 01 00 00 00 81 c6 f6 62 48 ed 01 c6 81 f9 29 48 00 01 75 b1 } //3
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*3+(#a_01_4  & 1)*3+(#a_01_5  & 1)*3) >=5
 
}