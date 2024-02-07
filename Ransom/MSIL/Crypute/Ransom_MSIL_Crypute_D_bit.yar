
rule Ransom_MSIL_Crypute_D_bit{
	meta:
		description = "Ransom:MSIL/Crypute.D!bit,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 06 00 00 02 00 "
		
	strings :
		$a_01_0 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 77 00 77 00 77 00 2e 00 64 00 69 00 61 00 6f 00 63 00 68 00 61 00 70 00 61 00 69 00 2e 00 63 00 6f 00 6d 00 2f 00 73 00 75 00 72 00 76 00 65 00 79 00 2f 00 } //01 00  http://www.diaochapai.com/survey/
		$a_01_1 = {5c 00 5c 00 73 00 65 00 6e 00 64 00 42 00 61 00 63 00 6b 00 5f 00 52 00 53 00 41 00 6b 00 65 00 79 00 2e 00 63 00 6b 00 74 00 } //01 00  \\sendBack_RSAkey.ckt
		$a_01_2 = {5c 00 5c 00 73 00 65 00 63 00 72 00 65 00 74 00 41 00 45 00 53 00 5f 00 52 00 53 00 41 00 65 00 64 00 5f 00 62 00 61 00 73 00 65 00 36 00 34 00 65 00 64 00 2e 00 63 00 6b 00 74 00 } //01 00  \\secretAES_RSAed_base64ed.ckt
		$a_01_3 = {5c 00 63 00 6b 00 65 00 2e 00 63 00 6b 00 65 00 } //01 00  \cke.cke
		$a_01_4 = {69 00 6d 00 75 00 67 00 66 00 40 00 6f 00 75 00 74 00 6c 00 6f 00 6f 00 6b 00 2e 00 63 00 6f 00 6d 00 } //01 00  imugf@outlook.com
		$a_01_5 = {5c 52 61 6e 73 6f 6d 77 61 72 65 5c 52 61 6e 73 6f 6d 77 61 72 65 5c 6f 62 6a 5c 44 65 62 75 67 5c 52 2e 70 64 62 } //00 00  \Ransomware\Ransomware\obj\Debug\R.pdb
	condition:
		any of ($a_*)
 
}