
rule Ransom_Win64_FileCoder_SP_MTB{
	meta:
		description = "Ransom:Win64/FileCoder.SP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {49 20 61 6d 20 74 68 65 20 77 61 6c 72 75 73 2e 20 49 20 68 61 76 65 20 74 61 6b 65 6e 20 74 68 65 20 6c 69 62 65 72 74 79 20 6f 66 20 70 72 6f 74 65 63 74 69 6e 67 20 74 68 65 20 64 61 74 61 20 6f 6e 20 79 6f 75 72 20 6d 61 63 68 69 6e 65 20 62 79 20 65 6e 63 72 79 70 74 69 6e 67 20 69 74 20 61 6c 6c } //1 I am the walrus. I have taken the liberty of protecting the data on your machine by encrypting it all
		$a_81_1 = {43 3a 5c 66 6c 61 67 2e 74 78 74 2e 74 75 73 6b } //1 C:\flag.txt.tusk
		$a_81_2 = {43 3a 5c 44 45 43 52 59 50 54 5f 59 4f 55 52 5f 46 49 4c 45 53 2e 74 78 74 } //1 C:\DECRYPT_YOUR_FILES.txt
		$a_81_3 = {72 65 70 6f 73 5c 54 75 73 6b 4c 6f 63 6b 65 72 32 5c 78 36 34 5c 52 65 6c 65 61 73 65 5c 54 75 73 6b 4c 6f 63 6b 65 72 32 2e 70 64 62 } //1 repos\TuskLocker2\x64\Release\TuskLocker2.pdb
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}