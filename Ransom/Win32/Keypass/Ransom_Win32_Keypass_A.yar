
rule Ransom_Win32_Keypass_A{
	meta:
		description = "Ransom:Win32/Keypass.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {61 00 6c 00 6e 00 75 00 6d 00 61 00 6c 00 70 00 68 00 61 00 62 00 6c 00 61 00 6e 00 6b 00 63 00 6e 00 74 00 72 00 6c 00 64 00 69 00 67 00 69 00 74 00 67 00 72 00 61 00 70 00 68 00 6c 00 6f 00 77 00 65 00 72 00 70 00 72 00 69 00 6e 00 74 00 70 00 75 00 6e 00 63 00 74 00 73 00 70 00 61 00 63 00 65 00 75 00 6e 00 69 00 63 00 6f 00 64 00 65 00 75 00 70 00 70 00 65 00 72 00 76 00 77 00 6f 00 72 00 64 00 78 00 64 00 69 00 67 00 69 00 74 00 } //1 alnumalphablankcntrldigitgraphlowerprintpunctspaceunicodeuppervwordxdigit
		$a_01_1 = {5c 00 78 00 7b 00 32 00 30 00 32 00 38 00 7d 00 5c 00 78 00 7b 00 32 00 30 00 32 00 39 00 7d 00 5d 00 29 00 } //1 \x{2028}\x{2029}])
		$a_01_2 = {5c 44 6f 63 5c 4d 79 20 77 6f 72 6b 20 28 43 2b 2b 29 5c 5f 4e 65 77 20 32 30 31 38 5c 45 6e 63 72 79 70 74 69 6f 6e 5c 52 65 6c 65 61 73 65 5c 65 6e 63 72 79 70 74 2e 70 64 62 } //1 \Doc\My work (C++)\_New 2018\Encryption\Release\encrypt.pdb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}