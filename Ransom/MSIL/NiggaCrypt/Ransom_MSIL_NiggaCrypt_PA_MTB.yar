
rule Ransom_MSIL_NiggaCrypt_PA_MTB{
	meta:
		description = "Ransom:MSIL/NiggaCrypt.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {52 5f 41 5f 4e 5f 53 5f 4f 5f 4d 5f 57 5f 41 5f 52 5f 45 5f 5f 5f 46 5f 4f 5f 52 5f 5f 5f 59 5f 4f 5f 55 5f 5f 5f 4e 5f 49 5f 47 5f 47 5f 41 } //1 R_A_N_S_O_M_W_A_R_E___F_O_R___Y_O_U___N_I_G_G_A
		$a_01_1 = {5c 00 52 00 45 00 41 00 44 00 5f 00 4d 00 45 00 5f 00 46 00 41 00 47 00 47 00 4f 00 54 00 2e 00 74 00 78 00 74 00 } //1 \READ_ME_FAGGOT.txt
		$a_01_2 = {5c 48 65 72 61 78 77 61 72 65 2e 70 64 62 } //1 \Heraxware.pdb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}