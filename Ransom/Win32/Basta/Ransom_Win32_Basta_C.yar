
rule Ransom_Win32_Basta_C{
	meta:
		description = "Ransom:Win32/Basta.C,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 07 00 00 "
		
	strings :
		$a_00_0 = {59 6f 75 72 20 64 61 74 61 20 61 72 65 20 73 74 6f 6c 65 6e 20 61 6e 64 20 65 6e 63 72 79 70 74 65 64 } //1 Your data are stolen and encrypted
		$a_00_1 = {54 68 65 20 64 61 74 61 20 77 69 6c 6c 20 62 65 20 70 75 62 6c 69 73 68 65 64 20 6f 6e 20 54 4f 52 20 77 65 62 73 69 74 65 20 69 66 20 79 6f 75 20 64 6f 20 6e 6f 74 20 70 61 79 20 74 68 65 20 72 61 6e 73 6f 6d } //1 The data will be published on TOR website if you do not pay the ransom
		$a_00_2 = {59 6f 75 72 20 63 6f 6d 70 61 6e 79 20 69 64 20 66 6f 72 20 6c 6f 67 20 69 6e 3a } //1 Your company id for log in:
		$a_00_3 = {59 6f 75 20 63 61 6e 20 63 6f 6e 74 61 63 74 20 75 73 20 61 6e 64 20 64 65 63 72 79 70 74 20 6f 6e 65 20 66 69 6c 65 20 66 6f 72 20 66 72 65 65 } //1 You can contact us and decrypt one file for free
		$a_02_4 = {2e 00 62 00 61 00 73 00 74 00 61 00 00 90 08 00 02 66 00 61 00 78 00 } //2
		$a_02_5 = {62 00 6f 00 6f 00 74 00 [0-10] 72 00 65 00 61 00 64 00 6d 00 65 00 2e 00 74 00 78 00 74 00 [0-30] 2e 00 6a 00 70 00 67 00 } //2
		$a_00_6 = {44 6f 6e 65 20 74 69 6d 65 3a 20 25 2e 34 66 20 73 65 63 6f 6e 64 73 2c 20 65 6e 63 72 79 70 74 65 64 3a 20 25 2e 34 66 20 67 62 } //2 Done time: %.4f seconds, encrypted: %.4f gb
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_02_4  & 1)*2+(#a_02_5  & 1)*2+(#a_00_6  & 1)*2) >=6
 
}