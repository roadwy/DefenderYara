
rule Ransom_Linux_Filecoder_E_MTB{
	meta:
		description = "Ransom:Linux/Filecoder.E!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,06 00 06 00 07 00 00 "
		
	strings :
		$a_00_0 = {e8 5e a8 fb ff 48 8b 84 24 10 08 00 00 69 f0 e8 03 00 00 48 8b 8c 24 18 08 00 00 48 ba cf f7 53 e3 a5 9b c4 20 48 89 c8 48 f7 ea 48 c1 fa 07 48 89 c8 48 c1 f8 3f 48 29 c2 48 89 d0 01 f0 89 c7 e8 be a6 fb ff 48 8b 05 ff 43 21 00 48 89 c1 ba 1a 00 00 00 be 01 00 00 00 } //1
		$a_00_1 = {2e 6e 75 63 74 65 63 68 2d 67 6a 30 6f 6b 79 63 69 } //1 .nuctech-gj0okyci
		$a_00_2 = {7c 2e 74 78 74 7c 2e 6a 73 7c 2e 78 6d 6c 7c 2e 6d 61 74 7c 2e 64 6f 63 7c 2e 78 6c 73 78 7c 2e 68 74 6d 7c 2e 78 6c 73 7c 2e 64 6f 63 78 7c 2e 70 79 7c 2e 68 7c 2e 68 74 6d 6c } //1 |.txt|.js|.xml|.mat|.doc|.xlsx|.htm|.xls|.docx|.py|.h|.html
		$a_00_3 = {72 65 61 64 6d 65 5f 74 6f 5f 6e 75 63 74 65 63 68 2e 74 78 74 } //1 readme_to_nuctech.txt
		$a_00_4 = {2d 2d 64 69 73 61 62 6c 65 2d 72 61 6e 73 6f 6d 66 69 6c 65 } //1 --disable-ransomfile
		$a_00_5 = {65 6e 63 72 79 70 74 5f 64 65 63 72 79 70 74 5f 66 69 6c 65 73 5f 61 66 74 65 72 5f 79 65 61 72 73 } //1 encrypt_decrypt_files_after_years
		$a_00_6 = {6f 4c 6f 43 4f 49 6e 61 46 58 40 6f 6e 69 6f 6e 6d 61 69 6c 2e 6f 72 67 } //1 oLoCOInaFX@onionmail.org
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=6
 
}