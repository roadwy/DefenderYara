
rule Trojan_Win32_Kryptik_AB_MTB{
	meta:
		description = "Trojan:Win32/Kryptik.AB!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b c8 34 aa 98 68 04 6e aa 6d 2c 41 66 0f ab d8 0f a4 d8 50 b8 6d f9 a7 65 f9 2b d2 f7 f1 f8 81 fd d5 6f d8 3d 31 05 58 ff 18 01 e9 } //1
		$a_01_1 = {8b 04 b1 66 c1 ef 97 2b f9 89 4c 24 0c c1 d7 cd 66 0f bc c9 8d 04 28 c0 dd 63 89 6c 24 08 66 81 fc c0 47 bf ff ff ff ff 0f be 6c 38 01 41 83 c7 01 f5 b9 4e 6c 0c 27 0f be 0c 3b f9 3b e9 e9 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}