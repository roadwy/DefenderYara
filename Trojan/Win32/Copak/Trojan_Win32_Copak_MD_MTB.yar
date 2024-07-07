
rule Trojan_Win32_Copak_MD_MTB{
	meta:
		description = "Trojan:Win32/Copak.MD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 03 00 00 "
		
	strings :
		$a_01_0 = {4d 5a 95 5c 39 15 f9 a6 bd 15 0d a5 3f 89 22 89 3b 22 22 f9 22 22 15 15 12 5c 15 22 15 15 15 2d 15 22 15 22 bf 22 22 c1 3f 3f 22 6d 22 15 8d 15 15 } //5
		$a_01_1 = {3f 0d 6d 15 3f 22 6d 3f 76 15 22 80 00 00 00 0e 1f ba 0e 00 b4 09 cd 21 b8 01 4c cd 21 54 68 69 73 20 70 72 6f 67 72 61 6d 20 63 61 6e 6e 6f } //5
		$a_01_2 = {e0 00 0f 03 0b 01 03 04 c0 78 00 00 00 cc 00 00 20 69 01 00 d8 85 } //5
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5) >=15
 
}