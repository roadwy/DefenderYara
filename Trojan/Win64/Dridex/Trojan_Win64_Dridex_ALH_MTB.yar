
rule Trojan_Win64_Dridex_ALH_MTB{
	meta:
		description = "Trojan:Win64/Dridex.ALH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 06 00 00 "
		
	strings :
		$a_80_0 = {73 64 6d 66 7c 65 72 2e 70 64 62 } //sdmf|er.pdb  3
		$a_80_1 = {43 72 79 70 74 49 6d 70 6f 72 74 50 75 62 6c 69 63 4b 65 79 49 6e 66 6f } //CryptImportPublicKeyInfo  3
		$a_80_2 = {72 61 69 73 69 6e 67 6e 35 38 37 } //raisingn587  3
		$a_80_3 = {61 69 6e 63 6c 75 64 69 6e 67 31 70 } //aincluding1p  3
		$a_80_4 = {4c 64 72 47 65 74 50 72 6f 63 65 64 75 72 65 41 64 64 72 65 73 73 } //LdrGetProcedureAddress  3
		$a_80_5 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //VirtualAlloc  3
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3) >=18
 
}