
rule Trojan_Win32_Viknok_patched{
	meta:
		description = "Trojan:Win32/Viknok!patched,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {81 ef 63 3c 22 05 81 c7 63 3c 22 05 66 81 c1 a9 79 66 81 e9 a9 79 51 81 c1 22 1c 00 00 8a 9c 31 dd e3 ff ff 59 05 d7 c6 78 25 2d d7 c6 78 25 32 d8 66 2d dd 18 66 05 dd 18 52 81 c2 43 01 00 00 66 89 9c 4a bb fe ff ff 5a 81 c3 4c 80 5a 57 81 eb 4c 80 5a 57 49 75 a8 80 ec d6 } //1
		$a_03_1 = {81 ef 51 6a 00 00 8d 8f 51 6a 00 00 5f 66 81 ea 63 bf 66 81 c2 63 bf 51 81 eb 21 fd 4e 28 81 c3 21 fd 4e 28 68 ?? ?? ?? ?? 58 04 69 2c 69 ff d0 } //1
		$a_01_2 = {66 89 87 3a 54 00 00 81 c7 14 54 00 00 66 81 e9 4e 3c 66 81 c1 4e 3c e8 fb 05 00 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}