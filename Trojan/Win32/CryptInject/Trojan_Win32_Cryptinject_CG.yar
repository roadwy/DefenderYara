
rule Trojan_Win32_Cryptinject_CG{
	meta:
		description = "Trojan:Win32/Cryptinject.CG,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {53 ff 75 f0 56 e8 42 ff ff ff 89 45 e4 53 ff 75 f0 56 e8 35 ff ff ff 89 45 e0 8b 7d 08 89 f1 41 99 f7 f9 89 c2 01 fa 52 8b 55 e4 89 f1 d3 fa 01 fa 52 e8 fb fe ff ff 83 c4 20 ff 45 e8 81 7d e8 e8 07 00 00 7c ba ff 45 fc 8b 45 f8 89 f2 42 0f af c2 39 45 fc 0f 8e 6d ff ff ff } //1
		$a_01_1 = {f7 e1 89 45 f4 a3 f0 6c 42 00 a1 e8 6c 42 00 31 f0 05 55 ed 00 00 a3 e8 6c 42 00 8b 3d e8 6c 42 00 89 f0 89 f9 80 c9 01 f7 e1 89 45 f0 89 c2 89 f8 2b 45 f0 b9 4b 0a 01 00 31 d2 f7 f1 89 15 e8 6c 42 00 8b 3d ec 6c 42 00 b8 99 07 01 00 89 f9 89 f2 d3 e2 01 d7 f7 e7 89 45 ec a3 ec 6c 42 00 b8 39 64 04 00 8b 0d fc 6c 42 00 31 f1 f7 e1 89 45 e8 a3 fc 6c 42 00 8b 3d e4 6c 42 00 89 f1 d3 ef 81 c7 a7 1d 01 00 89 3d e4 6c 42 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}