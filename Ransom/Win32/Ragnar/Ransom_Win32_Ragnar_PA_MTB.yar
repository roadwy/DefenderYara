
rule Ransom_Win32_Ragnar_PA_MTB{
	meta:
		description = "Ransom:Win32/Ragnar.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {73 65 6e 73 69 74 69 76 65 20 66 69 6c 65 73 20 77 65 72 65 20 43 4f 4d 50 52 4f 4d 49 53 45 44 } //1 sensitive files were COMPROMISED
		$a_01_1 = {65 6e 63 72 79 70 74 20 79 6f 75 72 20 66 69 6c 65 73 20 61 6e 64 20 73 65 72 76 65 72 73 } //1 encrypt your files and servers
		$a_01_2 = {65 76 65 72 79 74 68 69 6e 67 20 77 69 6c 6c 20 62 65 20 50 55 42 4c 49 53 48 } //1 everything will be PUBLISH
		$a_01_3 = {5f 00 52 00 45 00 41 00 44 00 4d 00 45 00 5f 00 4e 00 4f 00 54 00 45 00 53 00 5f 00 52 00 41 00 47 00 4e 00 41 00 52 00 5f 00 } //1 _README_NOTES_RAGNAR_
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}