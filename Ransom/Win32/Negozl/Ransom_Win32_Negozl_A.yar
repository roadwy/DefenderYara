
rule Ransom_Win32_Negozl_A{
	meta:
		description = "Ransom:Win32/Negozl.A,SIGNATURE_TYPE_PEHSTR,03 00 03 00 05 00 00 "
		
	strings :
		$a_01_0 = {2e 65 76 69 6c } //1 .evil
		$a_01_1 = {41 6c 6c 20 79 6f 75 72 20 61 74 74 65 6d 70 74 73 20 74 6f 20 72 65 73 74 6f 72 65 20 66 69 6c 65 73 20 6f 6e 20 74 68 65 69 72 20 6f 77 6e 2c 20 6c 65 61 64 20 74 6f 20 74 68 65 20 6c 6f 73 73 20 6f 66 20 74 68 65 20 70 6f 73 73 69 62 69 6c 69 74 79 20 6f 66 20 72 65 63 6f 76 65 72 79 20 61 6e 64 20 77 65 20 61 72 65 20 6e 6f 74 20 67 6f 69 6e 67 20 74 6f 20 68 65 6c 70 20 79 6f 75 2e 3c } //1 All your attempts to restore files on their own, lead to the loss of the possibility of recovery and we are not going to help you.<
		$a_01_2 = {4e 65 67 6f 7a 49 20 52 6e 73 6d } //1 NegozI Rnsm
		$a_01_3 = {52 65 6d 69 6e 64 4d 65 5f 52 61 6e 73 6f 6d } //1 RemindMe_Ransom
		$a_01_4 = {5c 44 45 43 52 59 50 54 5f 59 4f 55 52 5f 46 49 4c 45 53 2e 48 54 4d 4c } //1 \DECRYPT_YOUR_FILES.HTML
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=3
 
}