
rule Ransom_Win32_Cryak_PA_MTB{
	meta:
		description = "Ransom:Win32/Cryak.PA!MTB,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {68 00 6f 00 77 00 5f 00 74 00 6f 00 5f 00 64 00 65 00 63 00 72 00 79 00 70 00 74 00 2e 00 68 00 74 00 61 00 } //1 how_to_decrypt.hta
		$a_01_1 = {64 65 6c 65 74 65 20 73 68 61 64 6f 77 73 20 2f 61 6c 6c 20 2f 71 75 69 65 74 } //1 delete shadows /all /quiet
		$a_01_2 = {44 45 4c 45 54 45 20 42 41 43 4b 55 50 20 2d 6b 65 65 70 56 65 72 73 69 6f 6e 73 3a 30 } //1 DELETE BACKUP -keepVersions:0
		$a_01_3 = {2f 73 65 74 20 7b 64 65 66 61 75 6c 74 7d 20 72 65 63 6f 76 65 72 79 65 6e 61 62 6c 65 64 20 4e 6f } //1 /set {default} recoveryenabled No
		$a_01_4 = {41 6c 6c 20 79 6f 75 72 20 64 6f 63 75 6d 65 6e 74 73 2c 20 64 61 74 61 62 61 73 65 73 2c 20 62 61 63 6b 75 70 73 20 61 6e 64 20 6f 74 68 65 72 20 69 6d 70 6f 72 74 61 6e 74 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 } //1 All your documents, databases, backups and other important files have been encrypted
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}