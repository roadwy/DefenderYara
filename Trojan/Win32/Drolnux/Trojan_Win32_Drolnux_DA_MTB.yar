
rule Trojan_Win32_Drolnux_DA_MTB{
	meta:
		description = "Trojan:Win32/Drolnux.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {0f b6 74 24 27 8d 94 24 20 a0 05 00 c6 44 24 20 4d c6 44 24 21 5a c6 44 24 22 90 c6 44 24 23 00 c6 44 24 24 03 c6 44 24 25 00 c6 44 24 26 00 } //1
		$a_01_1 = {c6 44 24 27 00 0f b6 c8 8d 44 24 28 } //1
		$a_01_2 = {8d bc 27 00 00 00 00 28 08 83 c0 01 39 d0 75 } //1
		$a_81_3 = {25 63 3a 5c 2e 52 45 43 59 43 4c 45 52 5c 25 6c 73 2e 65 78 65 } //1 %c:\.RECYCLER\%ls.exe
		$a_81_4 = {4d 6f 6f 6e 63 68 69 6c 64 20 50 72 6f 64 75 63 74 69 6f 6e 73 } //1 Moonchild Productions
		$a_81_5 = {41 6d 69 73 68 65 6c 6c } //1 Amishell
		$a_81_6 = {61 48 52 30 63 44 6f 76 4c 32 49 7a 4c 6d 64 6c 4c 6e 52 30 4c 32 64 6c 64 48 51 76 4e 56 68 69 64 46 70 32 59 6a 49 76 62 6e 4e 7a 4d 79 35 6e 65 6a 39 70 62 6d 52 6c 65 44 30 78 } //1 aHR0cDovL2IzLmdlLnR0L2dldHQvNVhidFp2YjIvbnNzMy5nej9pbmRleD0x
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=7
 
}