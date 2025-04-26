
rule Ransom_Win32_Dedsec_A{
	meta:
		description = "Ransom:Win32/Dedsec.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 07 00 00 "
		
	strings :
		$a_01_0 = {44 45 44 53 45 43 20 52 41 4e 53 4f 4d 57 41 52 45 } //1 DEDSEC RANSOMWARE
		$a_01_1 = {74 2e 6d 65 2f 64 65 64 73 65 63 72 61 6e 73 6f 6d } //1 t.me/dedsecransom
		$a_01_2 = {5c 72 61 6e 73 6f 6d 2e 70 79 } //1 \ransom.py
		$a_01_3 = {59 4f 55 52 20 46 49 4c 45 53 20 48 41 56 45 20 42 45 45 4e 20 53 55 43 43 45 53 53 46 55 4c 4c 59 20 44 45 43 52 59 50 54 45 44 } //1 YOUR FILES HAVE BEEN SUCCESSFULLY DECRYPTED
		$a_01_4 = {55 6b 6c 47 52 6a 54 37 44 77 42 58 51 56 5a 46 5a 6d 31 30 49 42 41 41 41 41 41 42 41 41 45 41 67 44 34 41 41 41 42 39 41 41 41 43 41 42 41 41 5a 47 46 30 59 52 44 37 44 77 44 } //1 UklGRjT7DwBXQVZFZm10IBAAAAABAAEAgD4AAAB9AAACABAAZGF0YRD7DwD
		$a_01_5 = {65 6e 63 72 79 70 74 5f 66 69 6c 65 2e 3c 6c 6f 63 61 6c 73 3e 2e 3c 67 65 6e 65 78 70 72 3e } //1 encrypt_file.<locals>.<genexpr>
		$a_01_6 = {44 45 43 52 59 50 54 49 4f 4e 5f 4b 45 59 } //1 DECRYPTION_KEY
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=5
 
}