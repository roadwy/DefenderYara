
rule Trojan_Win32_Cosmu_ASB_MTB{
	meta:
		description = "Trojan:Win32/Cosmu.ASB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {92 65 76 91 47 4e 02 a5 49 6b 89 f4 8e 56 5b 3b 87 ee 0d a2 37 10 49 68 ec aa a9 2e 8d c5 2d ed fc 8d 2b dd 94 ee 87 4c 8c e4 a2 d8 96 3d ad 27 93 1c ac 97 eb 22 d6 b4 0b ea 6e a1 5d d6 e6 61 } //01 00 
		$a_01_1 = {9e 78 06 01 55 3a 83 83 dd 5d f9 73 2a 67 a4 e5 56 95 e9 af 16 1a 29 1d 0f 1d 07 bf 54 a7 72 ec 1a b4 9a e8 07 8f d9 72 ab 53 a9 e5 b5 db 48 e9 33 ca b7 88 a7 fa aa b7 5c c8 d0 b7 45 12 83 84 f0 0e 7e 8b 9c 68 22 39 40 38 40 13 6c 53 69 1d } //00 00 
	condition:
		any of ($a_*)
 
}