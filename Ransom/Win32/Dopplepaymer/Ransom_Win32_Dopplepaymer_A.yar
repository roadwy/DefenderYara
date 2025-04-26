
rule Ransom_Win32_Dopplepaymer_A{
	meta:
		description = "Ransom:Win32/Dopplepaymer.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {23 00 68 00 65 00 72 00 6a 00 57 00 52 00 4a 00 40 00 33 00 34 00 79 00 68 00 65 00 72 00 6a 00 65 00 72 00 } //2 #herjWRJ@34yherjer
		$a_00_1 = {41 73 73 6f 63 49 73 44 61 6e 67 65 72 6f 75 73 } //2 AssocIsDangerous
	condition:
		((#a_01_0  & 1)*2+(#a_00_1  & 1)*2) >=4
 
}
rule Ransom_Win32_Dopplepaymer_A_2{
	meta:
		description = "Ransom:Win32/Dopplepaymer.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b dd 32 c0 8b cb fe c0 d1 e9 8b d1 81 f2 20 83 b8 ed f6 c3 01 8b da 0f 44 d9 3c 08 7c e6 89 1c ae 45 81 fd 00 01 00 00 7c d6 } //2
		$a_01_1 = {0f b6 33 4a 33 f0 43 81 e6 ff 00 00 00 c1 e8 08 33 04 b1 83 fa ff 75 e8 } //1
		$a_01_2 = {0f b6 44 24 08 c1 e0 08 0f b6 4a 11 03 c1 c6 42 10 01 80 3a 00 74 16 8b 7a 08 8b 4a 04 66 89 04 79 ff 42 08 85 c0 75 11 33 c0 40 eb 0e } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule Ransom_Win32_Dopplepaymer_A_3{
	meta:
		description = "Ransom:Win32/Dopplepaymer.A,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_00_0 = {72 00 6a 00 35 00 37 00 63 00 73 00 39 00 64 00 6d 00 61 00 66 00 59 00 4b 00 4e 00 35 00 42 00 71 00 4b 00 38 00 4f 00 6f 00 75 00 44 00 43 00 } //1 rj57cs9dmafYKN5BqK8OouDC
	condition:
		((#a_00_0  & 1)*1) >=1
 
}
rule Ransom_Win32_Dopplepaymer_A_4{
	meta:
		description = "Ransom:Win32/Dopplepaymer.A,SIGNATURE_TYPE_PEHSTR,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {2e 00 72 00 65 00 61 00 64 00 6d 00 65 00 32 00 75 00 6e 00 6c 00 6f 00 63 00 6b 00 2e 00 74 00 78 00 74 00 } //2 .readme2unlock.txt
		$a_01_1 = {2e 00 6c 00 6f 00 63 00 6b 00 65 00 64 00 } //1 .locked
		$a_01_2 = {57 00 49 00 4e 00 44 00 4f 00 57 00 53 00 5c 00 53 00 59 00 53 00 54 00 45 00 4d 00 33 00 32 00 5c 00 2a 00 2e 00 64 00 6c 00 6c 00 } //1 WINDOWS\SYSTEM32\*.dll
		$a_01_3 = {46 69 6c 65 20 69 73 20 6c 6f 63 6b 65 64 3a 20 25 77 73 } //1 File is locked: %ws
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}
rule Ransom_Win32_Dopplepaymer_A_5{
	meta:
		description = "Ransom:Win32/Dopplepaymer.A,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {66 b8 17 a1 8b 4c 24 10 89 4c 24 14 8b 4c 24 14 8b 54 24 04 8a 1c 0a 66 8b 74 24 0e 88 5c 24 1b 66 69 7c 24 2e 63 f2 8b 0c 24 03 4c 24 14 66 89 7c 24 2e 89 4c 24 1c 66 39 f0 76 15 c7 44 24 10 00 00 00 00 eb ba 8b 04 24 8d 65 f4 5e 5f 5b 5d c3 8b 44 24 30 8b 4c 24 28 83 f1 ff 35 a9 86 ef 37 89 4c 24 28 8b 4c 24 1c 8a 54 24 1b 88 11 03 44 24 14 89 44 24 10 8b 4c 24 08 39 c8 74 c7 e9 7c ff } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}