
rule Trojan_Win64_Dridex_DV_MTB{
	meta:
		description = "Trojan:Win64/Dridex.DV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 "
		
	strings :
		$a_80_0 = {46 47 54 37 74 2e 70 64 62 } //FGT7t.pdb  3
		$a_80_1 = {43 72 79 70 74 41 63 71 75 69 72 65 43 65 72 74 69 66 69 63 61 74 65 50 72 69 76 61 74 65 4b 65 79 } //CryptAcquireCertificatePrivateKey  3
		$a_80_2 = {68 65 6f 6e 36 24 } //heon6$  3
		$a_80_3 = {36 77 55 76 78 71 55 76 } //6wUvxqUv  3
		$a_80_4 = {72 61 69 73 69 6e 67 6e 35 38 37 } //raisingn587  3
		$a_80_5 = {61 69 6e 63 6c 75 64 69 6e 67 31 70 } //aincluding1p  3
		$a_80_6 = {52 2e 5c 79 51 5a 4e 74 79 6f 6f 66 } //R.\yQZNtyoof  3
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3+(#a_80_6  & 1)*3) >=21
 
}