
rule Worm_Win32_Hamweq_AI{
	meta:
		description = "Worm:Win32/Hamweq.AI,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_03_0 = {7e 15 8b 06 8b 4c 24 ?? 03 c3 51 8a 14 29 30 10 45 ff d7 3b e8 7c eb 8b 06 03 c3 } //3
		$a_01_1 = {57 65 44 44 69 6e 67 73 20 53 65 72 76 69 43 45 } //1 WeDDings ServiCE
		$a_01_2 = {43 6f 64 65 64 20 03 34 42 79 20 03 38 56 69 72 55 73 2e 2e } //1
		$a_01_3 = {7b 36 37 58 4f 52 32 42 30 2d 33 47 4d 43 2d 38 39 56 56 2d 4a 49 4a 31 2d 33 32 4b 4c 35 52 33 34 32 34 34 34 34 7d } //1 {67XOR2B0-3GMC-89VV-JIJ1-32KL5R3424444}
		$a_01_4 = {78 58 78 5f 78 5f 31 00 44 45 57 2e 65 78 65 00 } //1 塸彸彸1䕄⹗硥e
		$a_01_5 = {59 41 4d 30 53 34 48 33 6c 59 61 52 41 42 49 74 53 6d 59 57 65 44 44 69 4e 67 00 } //1
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}