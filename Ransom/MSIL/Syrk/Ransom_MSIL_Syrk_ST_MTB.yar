
rule Ransom_MSIL_Syrk_ST_MTB{
	meta:
		description = "Ransom:MSIL/Syrk.ST!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_81_0 = {5c 44 6f 63 75 6d 65 6e 74 73 5c 44 65 6c 65 74 65 46 69 6c 65 2e 65 78 65 } //1 \Documents\DeleteFile.exe
		$a_81_1 = {59 6f 75 72 20 70 65 72 73 6f 6e 61 6c 20 66 69 6c 65 73 20 61 72 65 20 62 65 69 6e 67 20 65 6e 63 72 79 70 74 65 64 20 62 79 20 53 79 72 6b 20 4d 61 6c 77 61 72 65 2e } //1 Your personal files are being encrypted by Syrk Malware.
		$a_81_2 = {41 66 74 65 72 20 70 61 79 69 6e 67 2c 20 79 6f 75 20 77 69 6c 6c 20 62 65 20 73 65 6e 74 20 61 20 70 61 73 73 77 6f 72 64 20 74 68 61 74 20 77 69 6c 6c 20 62 65 20 75 73 65 64 20 74 6f 20 64 65 63 72 79 70 74 20 79 6f 75 72 20 66 69 6c 65 73 } //1 After paying, you will be sent a password that will be used to decrypt your files
		$a_81_3 = {69 66 20 79 6f 75 20 64 6f 6e 27 74 20 64 6f 20 74 68 65 73 65 20 61 63 74 69 6f 6e 73 20 62 65 66 6f 72 65 20 74 68 65 20 74 69 6d 65 72 20 65 78 70 69 72 65 73 20 79 6f 75 72 20 66 69 6c 65 73 20 77 69 6c 6c 20 73 74 61 72 74 20 74 6f 20 62 65 20 64 65 6c 65 74 65 64 } //1 if you don't do these actions before the timer expires your files will start to be deleted
		$a_81_4 = {41 6c 6c 20 74 68 65 20 66 69 6c 65 73 20 69 6e 20 74 68 65 20 44 65 73 6b 74 6f 70 20 66 6f 6c 64 65 72 20 68 61 76 65 20 62 65 65 6e 20 64 65 6c 65 74 65 64 21 } //1 All the files in the Desktop folder have been deleted!
		$a_81_5 = {2a 2e 53 79 72 6b } //1 *.Syrk
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=5
 
}