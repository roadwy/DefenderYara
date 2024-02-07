
rule Ransom_Win32_Zepplin_B_MTB{
	meta:
		description = "Ransom:Win32/Zepplin.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_81_0 = {43 3a 5c 5c 50 6c 65 61 73 65 20 52 65 61 64 20 4d 65 21 21 21 2e 68 74 61 } //01 00  C:\\Please Read Me!!!.hta
		$a_81_1 = {44 3a 5c 5c 50 6c 65 61 73 65 20 52 65 61 64 20 4d 65 21 21 21 2e 68 74 61 } //01 00  D:\\Please Read Me!!!.hta
		$a_81_2 = {41 3a 5c 5c 50 6c 65 61 73 65 20 52 65 61 64 20 4d 65 21 21 21 2e 68 74 61 } //01 00  A:\\Please Read Me!!!.hta
		$a_81_3 = {42 3a 5c 5c 50 6c 65 61 73 65 20 52 65 61 64 20 4d 65 21 21 21 2e 68 74 61 } //01 00  B:\\Please Read Me!!!.hta
		$a_81_4 = {5c 44 6f 77 6e 6c 6f 61 64 73 5c 50 6c 65 61 73 65 20 52 65 61 64 20 4d 65 21 21 21 2e 68 74 61 } //01 00  \Downloads\Please Read Me!!!.hta
		$a_81_5 = {43 69 70 68 65 72 20 6e 6f 74 20 69 6e 69 74 69 61 6c 69 7a 65 64 } //01 00  Cipher not initialized
		$a_81_6 = {5c 42 65 6e 69 5f 4f 6b 75 21 21 21 2e 68 74 61 } //01 00  \Beni_Oku!!!.hta
		$a_81_7 = {2e 74 78 74 3b 2e 64 6f 63 3b 2e 64 6f 63 78 3b 2e 69 6e 74 65 78 3b 2e 70 64 66 3b 2e 7a 69 70 3b 2e 72 61 72 3b 2e 6f 6e 65 74 6f 63 3b } //00 00  .txt;.doc;.docx;.intex;.pdf;.zip;.rar;.onetoc;
		$a_00_8 = {5d 04 00 00 } //9e 20 
	condition:
		any of ($a_*)
 
}