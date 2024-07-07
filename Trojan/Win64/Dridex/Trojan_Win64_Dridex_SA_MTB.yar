
rule Trojan_Win64_Dridex_SA_MTB{
	meta:
		description = "Trojan:Win64/Dridex.SA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 06 00 00 "
		
	strings :
		$a_80_0 = {72 61 69 73 69 6e 67 6e 35 38 37 } //raisingn587  3
		$a_80_1 = {61 69 6e 63 6c 75 64 69 6e 67 31 70 } //aincluding1p  3
		$a_80_2 = {46 47 54 37 74 2e 70 64 62 } //FGT7t.pdb  3
		$a_80_3 = {43 72 79 70 74 49 6d 70 6f 72 74 50 75 62 6c 69 63 4b 65 79 49 6e 66 6f } //CryptImportPublicKeyInfo  3
		$a_80_4 = {6f 54 5a 6e 69 6f 44 } //oTZnioD  3
		$a_80_5 = {43 52 59 50 54 33 32 2e 64 6c 6c } //CRYPT32.dll  3
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3) >=18
 
}