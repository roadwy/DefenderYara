
rule Trojan_Win32_ValleyRat_BSA_MTB{
	meta:
		description = "Trojan:Win32/ValleyRat.BSA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b 54 24 0c 8b 4c 24 04 85 d2 74 69 33 c0 8a 44 24 08 84 c0 75 16 81 fa 80 00 00 00 72 0e 83 3d 08 13 58 00 00 74 05 e9 0b 9d } //10
		$a_01_1 = {66 0f ef c0 51 53 8b c1 83 e0 0f 85 c0 75 7f 8b c2 83 e2 7f c1 e8 07 74 37 8d a4 24 } //5
		$a_01_2 = {8b d8 f7 db 83 c3 10 2b d3 33 c0 52 8b d3 83 e2 03 74 06 } //5
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5) >=20
 
}
rule Trojan_Win32_ValleyRat_BSA_MTB_2{
	meta:
		description = "Trojan:Win32/ValleyRat.BSA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 04 00 00 "
		
	strings :
		$a_03_0 = {55 8b ec 56 eb 13 ?? ?? ?? ?? ?? 85 c0 74 19 ff 75 08 ff d0 59 85 c0 74 0f ff 75 08 e8 97 e9 0f 00 8b f0 59 85 f6 74 de 8b c6 } //10
		$a_01_1 = {85 c0 74 19 ff 75 08 ff d0 59 85 c0 74 0f ff 75 08 } //2
		$a_03_2 = {ff 73 64 c7 45 d4 ?? ?? ?? ?? ff d6 6a 04 8d 45 d4 50 68 } //2
		$a_03_3 = {8b 44 24 10 89 6c 24 10 8d 6c 24 10 2b e0 53 56 57 a1 ?? ?? ?? ?? 31 45 fc 33 c5 50 89 65 e8 ff 75 f8 8b 45 fc c7 45 fc ?? ?? ?? ?? 89 45 f8 8d 45 f0 64 a3 00 } //8
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*2+(#a_03_2  & 1)*2+(#a_03_3  & 1)*8) >=22
 
}