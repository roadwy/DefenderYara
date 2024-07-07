
rule Trojan_Win32_Copak_DQ_MTB{
	meta:
		description = "Trojan:Win32/Copak.DQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 1a 81 e9 59 5c 36 5f 4f 81 e3 ff 00 00 00 46 29 fe 31 18 4f 47 40 f7 d1 47 81 c2 01 00 00 00 89 cf 09 ff 81 ef 1d e2 70 fc 81 f8 b8 af 47 00 0f } //2
		$a_01_1 = {8b 3e 4b 09 c8 81 e7 ff 00 00 00 01 c3 f7 d3 21 d8 31 3a 89 d8 41 42 09 db 48 46 81 c1 0a 05 d9 3d 81 c3 34 a9 b3 d4 81 fa b8 af 47 00 0f } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=2
 
}