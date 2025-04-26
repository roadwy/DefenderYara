
rule Ransom_Win32_Polyglot_A_{
	meta:
		description = "Ransom:Win32/Polyglot.A!!Polyglot.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_80_0 = {73 65 74 43 72 79 70 74 65 64 46 69 6c 65 } //setCryptedFile  1
		$a_80_1 = {23 64 65 63 72 79 70 74 5f 64 65 6d 6f 5f 66 69 6c 65 73 } //#decrypt_demo_files  1
		$a_80_2 = {52 65 61 64 4d 65 46 69 6c 65 73 44 65 63 72 79 70 74 2e 74 78 74 21 21 21 } //ReadMeFilesDecrypt.txt!!!  1
		$a_80_3 = {66 75 6e 63 74 69 6f 6e 20 70 72 65 73 73 5f 64 65 6d 6f 5f 64 65 63 72 79 70 74 28 29 0d 0a 7b 0d 0a 09 76 69 73 69 62 6c 65 45 6c 65 6d 65 6e 74 73 28 22 62 5f 64 65 6d 6f 5f 64 65 63 72 79 70 74 22 29 3b } //function press_demo_decrypt()
{
	visibleElements("b_demo_decrypt");  2
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*2) >=4
 
}