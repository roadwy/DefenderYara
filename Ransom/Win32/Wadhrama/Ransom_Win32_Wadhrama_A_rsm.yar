
rule Ransom_Win32_Wadhrama_A_rsm{
	meta:
		description = "Ransom:Win32/Wadhrama.A!rsm,SIGNATURE_TYPE_PEHSTR,03 00 03 00 05 00 00 "
		
	strings :
		$a_01_0 = {3a 5c 63 72 79 73 69 73 5c 52 65 6c 65 61 73 65 5c 50 44 42 5c 70 61 79 6c 6f 61 64 2e 70 64 62 } //3 :\crysis\Release\PDB\payload.pdb
		$a_01_1 = {44 00 65 00 6e 00 69 00 65 00 64 00 20 00 49 00 4e 00 46 00 4f 00 52 00 4d 00 41 00 54 00 49 00 4f 00 4e 00 2e 00 74 00 78 00 74 00 00 00 } //1
		$a_01_2 = {3b 00 2e 00 6d 00 78 00 6c 00 3b 00 2e 00 6d 00 79 00 64 00 3b 00 2e 00 6d 00 79 00 69 00 3b 00 2e 00 6e 00 65 00 66 00 3b 00 2e 00 6e 00 72 00 77 00 3b 00 2e 00 6f 00 62 00 6a 00 3b 00 2e 00 } //1 ;.mxl;.myd;.myi;.nef;.nrw;.obj;.
		$a_01_3 = {63 6f 6e 20 63 70 20 73 65 6c 65 63 74 3d 31 32 35 31 } //1 con cp select=1251
		$a_01_4 = {64 65 6c 65 74 65 20 73 68 61 64 6f 77 73 20 2f 61 6c 6c 20 2f 71 75 69 65 74 } //1 delete shadows /all /quiet
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=3
 
}