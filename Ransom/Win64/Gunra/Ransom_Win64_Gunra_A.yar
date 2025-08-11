
rule Ransom_Win64_Gunra_A{
	meta:
		description = "Ransom:Win64/Gunra.A,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 04 00 00 "
		
	strings :
		$a_01_0 = {2e 00 45 00 4e 00 43 00 52 00 54 00 00 00 } //5
		$a_01_1 = {73 00 74 00 6f 00 70 00 6d 00 61 00 72 00 6b 00 65 00 72 00 00 00 } //5
		$a_01_2 = {42 75 74 20 79 6f 75 20 68 61 76 65 20 6e 6f 74 20 73 6f 20 65 6e 6f 75 67 68 20 74 69 6d 65 } //1 But you have not so enough time
		$a_01_3 = {59 4f 55 52 20 41 4c 4c 20 44 41 54 41 20 48 41 56 45 20 42 45 45 4e 20 45 4e 43 52 59 50 54 45 44 21 } //1 YOUR ALL DATA HAVE BEEN ENCRYPTED!
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=11
 
}