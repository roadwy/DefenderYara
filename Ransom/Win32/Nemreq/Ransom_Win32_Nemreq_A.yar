
rule Ransom_Win32_Nemreq_A{
	meta:
		description = "Ransom:Win32/Nemreq.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 08 00 00 "
		
	strings :
		$a_01_0 = {73 75 62 6d 69 74 3d 73 75 62 6d 69 74 26 69 64 3d 25 73 26 67 75 69 64 3d 25 73 26 70 63 3d 25 73 26 6d 61 69 6c 3d 25 73 00 } //1 畳浢瑩猽扵業♴摩┽♳畧摩┽♳捰┽♳慭汩┽s
		$a_01_1 = {76 73 73 61 64 6d 69 6e 20 64 65 6c 65 74 65 20 73 68 61 64 6f 77 73 20 2f 61 6c 6c 20 2f 71 75 69 65 74 } //1 vssadmin delete shadows /all /quiet
		$a_00_2 = {44 00 45 00 43 00 52 00 59 00 50 00 54 00 20 00 46 00 49 00 4c 00 45 00 53 00 20 00 45 00 4d 00 41 00 49 00 4c 00 } //1 DECRYPT FILES EMAIL
		$a_00_3 = {47 00 6c 00 6f 00 62 00 61 00 6c 00 5c 00 73 00 6e 00 63 00 5f 00 } //1 Global\snc_
		$a_00_4 = {48 00 6f 00 77 00 20 00 74 00 6f 00 20 00 64 00 65 00 63 00 72 00 79 00 70 00 74 00 20 00 79 00 6f 00 75 00 72 00 20 00 66 00 69 00 6c 00 65 00 73 00 2e 00 74 00 78 00 74 00 } //1 How to decrypt your files.txt
		$a_00_5 = {64 00 6f 00 63 00 28 00 2e 00 64 00 6f 00 63 00 3b 00 2e 00 64 00 6f 00 63 00 78 00 3b 00 2e 00 70 00 64 00 66 00 3b 00 2e 00 78 00 6c 00 73 00 3b 00 2e 00 78 00 6c 00 73 00 78 00 3b 00 2e 00 70 00 70 00 74 00 3b 00 29 00 } //1 doc(.doc;.docx;.pdf;.xls;.xlsx;.ppt;)
		$a_00_6 = {3b 00 44 00 65 00 63 00 72 00 79 00 70 00 74 00 69 00 6f 00 6e 00 20 00 69 00 6e 00 73 00 74 00 72 00 75 00 63 00 74 00 69 00 6f 00 6e 00 73 00 2e 00 6a 00 70 00 67 00 3b 00 44 00 65 00 63 00 72 00 79 00 70 00 74 00 69 00 6f 00 6e 00 73 00 20 00 69 00 6e 00 73 00 74 00 72 00 75 00 63 00 74 00 69 00 6f 00 6e 00 73 00 2e 00 74 00 78 00 74 00 3b 00 } //1 ;Decryption instructions.jpg;Decryptions instructions.txt;
		$a_00_7 = {43 3a 5c 63 72 79 73 69 73 5c 52 65 6c 65 61 73 65 5c 50 44 42 5c 70 61 79 6c 6f 61 64 2e 70 64 62 } //1 C:\crysis\Release\PDB\payload.pdb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1) >=4
 
}