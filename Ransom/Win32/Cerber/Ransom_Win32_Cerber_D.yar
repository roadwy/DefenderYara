
rule Ransom_Win32_Cerber_D{
	meta:
		description = "Ransom:Win32/Cerber.D,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {43 45 52 42 45 52 5f 4b 45 59 5f 50 4c 41 43 45 } //1 CERBER_KEY_PLACE
		$a_80_1 = {28 69 6e 20 79 6f 75 72 20 63 61 73 65 20 5c 22 43 65 72 62 65 72 20 44 65 63 72 79 70 74 6f 72 5c 22 20 73 6f 66 74 77 61 72 65 29 20 66 6f 72 20 73 61 66 65 20 61 6e 64 20 63 6f 6d 70 6c 65 74 65 } //(in your case \"Cerber Decryptor\" software) for safe and complete  1
		$a_81_2 = {31 2e 20 20 68 74 74 70 3a 2f 2f 7b 54 4f 52 7d 2e 7b 53 49 54 45 5f 31 7d 2f 7b 50 43 5f 49 44 7d } //1 1.  http://{TOR}.{SITE_1}/{PC_ID}
		$a_81_3 = {3c 68 33 3e 43 20 45 20 52 20 42 20 45 20 52 26 6e 62 73 70 3b 26 6e 62 73 70 3b 26 6e 62 73 70 3b 52 20 41 20 4e 20 53 20 4f 20 4d 20 57 20 41 20 52 20 45 3c 2f 68 33 3e } //1 <h3>C E R B E R&nbsp;&nbsp;&nbsp;R A N S O M W A R E</h3>
	condition:
		((#a_01_0  & 1)*1+(#a_80_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=3
 
}