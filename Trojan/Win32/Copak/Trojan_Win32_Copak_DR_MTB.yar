
rule Trojan_Win32_Copak_DR_MTB{
	meta:
		description = "Trojan:Win32/Copak.DR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {81 c1 f2 b6 21 03 81 c0 9f e8 0e eb e8 [0-04] 81 c1 2a 21 91 32 31 33 43 39 d3 75 } //2
		$a_01_1 = {21 d2 01 d1 81 c1 31 6f fc 73 5e 09 ca 29 d2 47 29 d1 4a 09 ca 81 ff 4e cc 00 01 75 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}
rule Trojan_Win32_Copak_DR_MTB_2{
	meta:
		description = "Trojan:Win32/Copak.DR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {f7 d6 81 e2 ff 00 00 00 f7 d0 b8 24 77 f9 44 31 11 81 c0 f1 d6 28 f7 81 c3 67 c7 45 6c 21 de 81 c1 01 00 00 00 89 f3 be 0b a1 0b a8 47 81 eb dd 9c 8a 58 21 c3 09 db 81 f9 b8 af 47 00 0f } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}