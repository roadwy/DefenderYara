
rule Ransom_Win32_Petya_BA_MTB{
	meta:
		description = "Ransom:Win32/Petya.BA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 07 00 00 "
		
	strings :
		$a_81_0 = {52 41 4e 53 4f 4d 57 41 52 45 21 } //1 RANSOMWARE!
		$a_81_1 = {65 6e 63 72 79 70 74 69 6f 6e 20 61 6c 67 6f 72 69 74 68 6d 2e } //1 encryption algorithm.
		$a_81_2 = {54 6f 72 20 42 72 6f 77 73 65 72 } //1 Tor Browser
		$a_81_3 = {61 63 63 65 73 73 20 6f 6e 69 6f 6e 20 70 61 67 65 } //1 access onion page
		$a_02_4 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 [0-12] 2e 00 6f 00 6e 00 69 00 6f 00 6e 00 2f 00 } //1
		$a_02_5 = {68 74 74 70 3a 2f 2f [0-12] 2e 6f 6e 69 6f 6e 2f } //1
		$a_81_6 = {64 65 63 72 79 70 74 69 6f 6e 20 63 6f 64 65 } //1 decryption code
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_02_4  & 1)*1+(#a_02_5  & 1)*1+(#a_81_6  & 1)*1) >=6
 
}