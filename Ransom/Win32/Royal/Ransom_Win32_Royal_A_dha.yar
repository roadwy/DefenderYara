
rule Ransom_Win32_Royal_A_dha{
	meta:
		description = "Ransom:Win32/Royal.A!dha,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {64 00 65 00 6c 00 65 00 74 00 65 00 20 00 73 00 68 00 61 00 64 00 6f 00 77 00 73 00 20 00 2f 00 61 00 6c 00 6c 00 20 00 2f 00 71 00 75 00 69 00 65 00 74 00 } //1 delete shadows /all /quiet
		$a_01_1 = {2e 00 72 00 6f 00 79 00 61 00 6c 00 } //1 .royal
		$a_01_2 = {74 00 6f 00 72 00 20 00 62 00 72 00 6f 00 77 00 73 00 65 00 72 00 } //1 tor browser
		$a_01_3 = {41 45 53 20 66 6f 72 20 78 38 36 2c 20 43 52 59 50 54 4f 47 41 4d 53 20 62 79 20 3c 61 70 70 72 6f 40 6f 70 65 6e 73 73 6c 2e 6f 72 67 3e } //1 AES for x86, CRYPTOGAMS by <appro@openssl.org>
		$a_01_4 = {52 00 45 00 41 00 44 00 4d 00 45 00 2e 00 54 00 58 00 54 00 } //1 README.TXT
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}