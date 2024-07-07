
rule Ransom_Win32_Tazwit_A{
	meta:
		description = "Ransom:Win32/Tazwit.A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {78 6c 6b 00 78 6c 73 00 78 6c 73 62 00 78 6c 73 6d 00 78 6c 73 78 00 78 6d 6c 00 78 70 73 00 7a 69 70 00 78 78 78 } //1 汸k汸s汸扳砀獬m汸硳砀汭砀獰稀灩砀硸
		$a_01_1 = {46 52 4f 4d 20 54 48 45 20 57 48 31 54 45 48 34 54 5a 21 } //1 FROM THE WH1TEH4TZ!
		$a_01_2 = {59 4f 55 52 20 46 49 4c 45 53 20 42 45 4c 4f 4e 47 20 54 4f 20 55 53 } //1 YOUR FILES BELONG TO US
		$a_01_3 = {45 6d 61 69 6c 20 75 73 20 74 77 6f 20 65 6e 63 72 79 70 74 65 64 20 66 69 6c 65 73 20 61 6c 6f 6e 67 20 77 69 74 68 20 73 65 63 72 65 74 2e 6b 65 79 20 66 69 6c 65 } //1 Email us two encrypted files along with secret.key file
		$a_81_4 = {5c 4e 45 45 44 5f 52 45 41 44 2e 54 58 54 } //1 \NEED_READ.TXT
		$a_81_5 = {2e 77 34 7a 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}