
rule Ransom_Win64_Gentlemen_B{
	meta:
		description = "Ransom:Win64/Gentlemen.B,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {52 45 41 44 4d 45 2d 47 45 4e 54 4c 45 4d 45 4e 2e 74 78 74 } //1 README-GENTLEMEN.txt
		$a_01_1 = {45 72 72 6f 72 3a 20 2d 2d 73 68 61 72 65 73 20 61 6e 64 20 2d 2d 73 79 73 74 65 6d 20 63 61 6e 6e 6f 74 20 62 65 20 75 73 65 64 20 74 6f 67 65 74 68 65 72 2e } //1 Error: --shares and --system cannot be used together.
		$a_01_2 = {4c 61 74 65 72 61 6c 20 6d 6f 76 65 6d 65 6e 74 3a 20 64 6f 6d 61 69 6e 2f 75 73 65 72 3a 70 61 73 73 77 6f 72 64 20 28 6f 70 74 69 6f 6e 61 6c 29 } //1 Lateral movement: domain/user:password (optional)
		$a_01_3 = {5b 2b 5d 20 45 6e 63 72 79 70 74 69 6f 6e 20 73 74 61 72 74 65 64 2e 20 47 6f 69 6e 67 20 62 61 63 6b 67 72 6f 75 6e 64 2e 2e 2e } //1 [+] Encryption started. Going background...
		$a_01_4 = {67 65 6e 74 6c 65 6d 65 6e 2e 62 6d 70 } //1 gentlemen.bmp
		$a_01_5 = {67 65 6e 74 6c 65 6d 65 6e 5f 73 79 73 74 65 6d } //1 gentlemen_system
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}