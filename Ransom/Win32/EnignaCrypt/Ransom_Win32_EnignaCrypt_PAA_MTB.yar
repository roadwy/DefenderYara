
rule Ransom_Win32_EnignaCrypt_PAA_MTB{
	meta:
		description = "Ransom:Win32/EnignaCrypt.PAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {74 6f 72 70 72 6f 6a 65 63 74 } //1 torproject
		$a_81_1 = {65 6e 69 67 6d 61 5f 69 6e 66 6f 2e 74 78 74 } //1 enigma_info.txt
		$a_81_2 = {45 5f 4e 5f 49 5f 47 5f 4d 5f 41 2e 52 53 41 } //1 E_N_I_G_M_A.RSA
		$a_81_3 = {76 73 73 61 64 6d 69 6e 20 64 65 6c 65 74 65 20 73 68 61 64 6f 77 73 20 2f 61 6c 6c 20 2f 71 75 69 65 74 } //1 vssadmin delete shadows /all /quiet
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}