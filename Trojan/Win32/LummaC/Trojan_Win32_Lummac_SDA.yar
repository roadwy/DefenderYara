
rule Trojan_Win32_Lummac_SDA{
	meta:
		description = "Trojan:Win32/Lummac.SDA,SIGNATURE_TYPE_PEHSTR_EXT,73 00 73 00 07 00 00 "
		
	strings :
		$a_01_0 = {32 1d 30 f9 48 77 82 5a 3c bf 73 7f dd 4f 15 75 } //100
		$a_01_1 = {57 58 59 5a 00 78 58 00 } //5 塗婙砀X
		$a_03_2 = {ae 42 60 82 c7 ?? ?? ?? 49 45 4e 44 } //5
		$a_01_3 = {fe dc ba 98 76 54 32 10 f0 e1 d2 c3 } //5
		$a_01_4 = {b8 fe ff ff ff 90 90 90 90 90 90 90 90 } //5
		$a_80_5 = {63 72 79 70 74 6f 5c 65 76 70 5c 65 6e 63 6f 64 65 2e 63 2e 61 73 73 65 72 74 69 6f 6e } //crypto\evp\encode.c.assertion  -100
		$a_80_6 = {5c 6c 69 62 63 65 66 2e 64 6c 6c } //\libcef.dll  -100
	condition:
		((#a_01_0  & 1)*100+(#a_01_1  & 1)*5+(#a_03_2  & 1)*5+(#a_01_3  & 1)*5+(#a_01_4  & 1)*5+(#a_80_5  & 1)*-100+(#a_80_6  & 1)*-100) >=115
 
}