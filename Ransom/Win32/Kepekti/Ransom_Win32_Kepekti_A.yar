
rule Ransom_Win32_Kepekti_A{
	meta:
		description = "Ransom:Win32/Kepekti.A,SIGNATURE_TYPE_PEHSTR,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {45 00 6e 00 63 00 72 00 79 00 70 00 74 00 69 00 6f 00 6e 00 20 00 43 00 6f 00 6d 00 70 00 6c 00 65 00 74 00 65 00 } //1 Encryption Complete
		$a_01_1 = {54 00 4f 00 20 00 55 00 4e 00 4c 00 4f 00 43 00 4b 00 20 00 54 00 48 00 49 00 53 00 20 00 43 00 4f 00 4d 00 50 00 55 00 54 00 45 00 52 00 20 00 59 00 4f 00 55 00 20 00 41 00 52 00 45 00 20 00 4f 00 42 00 4c 00 49 00 47 00 45 00 44 00 20 00 54 00 4f 00 20 00 50 00 41 00 59 00 } //1 TO UNLOCK THIS COMPUTER YOU ARE OBLIGED TO PAY
		$a_01_2 = {4c 00 6f 00 63 00 61 00 6c 00 62 00 69 00 74 00 63 00 6f 00 69 00 6e 00 73 00 2e 00 63 00 6f 00 6d 00 } //1 Localbitcoins.com
		$a_01_3 = {42 75 69 6c 64 65 72 20 52 61 6e 73 6f 6d 2e 70 64 62 } //2 Builder Ransom.pdb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*2) >=5
 
}