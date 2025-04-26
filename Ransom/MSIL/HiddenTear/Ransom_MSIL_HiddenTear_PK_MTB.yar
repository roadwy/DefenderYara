
rule Ransom_MSIL_HiddenTear_PK_MTB{
	meta:
		description = "Ransom:MSIL/HiddenTear.PK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {76 00 73 00 73 00 61 00 64 00 6d 00 69 00 6e 00 2e 00 65 00 78 00 65 00 20 00 64 00 65 00 6c 00 65 00 74 00 65 00 20 00 73 00 68 00 61 00 64 00 6f 00 77 00 73 00 20 00 2f 00 61 00 6c 00 6c 00 20 00 2f 00 20 00 71 00 75 00 69 00 65 00 74 00 } //1 vssadmin.exe delete shadows /all / quiet
		$a_01_1 = {41 00 6c 00 6c 00 20 00 6f 00 66 00 20 00 79 00 6f 00 75 00 72 00 20 00 66 00 69 00 6c 00 65 00 73 00 20 00 68 00 61 00 76 00 65 00 20 00 62 00 65 00 65 00 6e 00 20 00 65 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 } //1 All of your files have been encrypted
		$a_01_2 = {48 00 45 00 4c 00 50 00 5f 00 44 00 45 00 43 00 52 00 59 00 50 00 54 00 5f 00 46 00 49 00 4c 00 45 00 53 00 2e 00 74 00 78 00 74 00 } //1 HELP_DECRYPT_FILES.txt
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}