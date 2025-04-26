
rule Ransom_MSIL_Shezkrypt_A{
	meta:
		description = "Ransom:MSIL/Shezkrypt.A,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 08 00 00 "
		
	strings :
		$a_80_0 = {76 73 73 61 64 6d 69 6e 20 64 65 6c 65 74 65 20 73 68 61 64 6f 77 73 20 2f 61 6c 6c 20 2f 71 75 69 65 74 } //vssadmin delete shadows /all /quiet  2
		$a_80_1 = {64 65 6c 65 74 65 4d 79 50 72 6f 67 72 61 6d 2e 62 61 74 } //deleteMyProgram.bat  2
		$a_80_2 = {2e 73 6f 72 72 79 } //.sorry  2
		$a_80_3 = {63 3a 5c 57 69 6e 64 6f 77 73 5c 68 72 66 2e 74 78 74 } //c:\Windows\hrf.txt  2
		$a_80_4 = {41 6c 6c 20 79 6f 75 72 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 45 4e 43 52 59 50 54 45 44 } //All your files have been ENCRYPTED  2
		$a_80_5 = {73 79 73 74 65 6d 73 40 68 69 74 6c 65 72 2e 72 6f 63 6b 73 } //systems@hitler.rocks  2
		$a_80_6 = {73 79 73 74 65 6d 73 40 74 75 74 61 6e 6f 74 61 2e 63 6f 6d } //systems@tutanota.com  2
		$a_80_7 = {48 6f 77 20 52 65 63 6f 76 65 72 79 20 46 69 6c 65 73 2e 74 78 74 } //How Recovery Files.txt  2
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*2+(#a_80_2  & 1)*2+(#a_80_3  & 1)*2+(#a_80_4  & 1)*2+(#a_80_5  & 1)*2+(#a_80_6  & 1)*2+(#a_80_7  & 1)*2) >=12
 
}