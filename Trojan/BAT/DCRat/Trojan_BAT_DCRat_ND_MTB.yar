
rule Trojan_BAT_DCRat_ND_MTB{
	meta:
		description = "Trojan:BAT/DCRat.ND!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {54 65 73 73 61 4c 65 74 4d 65 44 69 65 36 30 31 56 69 6f 6c 65 74 2e 6a 6e 66 76 71 71 } //2 TessaLetMeDie601Violet.jnfvqq
		$a_01_1 = {73 68 61 72 65 20 6c 61 7a 79 20 6a 75 6d 70 20 62 6c 75 65 20 64 61 74 61 62 61 73 65 20 76 69 73 69 6f 6e 20 75 6e 64 65 72 73 74 61 6e 64 20 79 6f 75 20 67 72 6f 77 20 64 61 72 6b } //1 share lazy jump blue database vision understand you grow dark
		$a_01_2 = {65 78 70 6c 6f 72 65 20 77 65 20 6d 6f 6f 6e } //1 explore we moon
		$a_01_3 = {24 66 36 34 37 61 66 61 31 2d 36 38 66 31 2d 34 38 35 39 2d 61 66 30 64 2d 30 39 64 62 38 32 31 65 30 64 33 62 } //1 $f647afa1-68f1-4859-af0d-09db821e0d3b
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}