
rule Ransom_Win32_FileCoder_BAA_MTB{
	meta:
		description = "Ransom:Win32/FileCoder.BAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {45 6e 63 72 79 70 74 65 64 } //1 Encrypted
		$a_81_1 = {59 6f 75 72 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 } //1 Your files have been encrypted
		$a_81_2 = {54 6f 20 72 65 63 6f 76 65 72 20 79 6f 75 72 20 64 61 74 61 } //1 To recover your data
		$a_81_3 = {4e 6f 74 65 20 64 72 6f 70 70 65 64 } //1 Note dropped
		$a_81_4 = {73 76 63 68 6f 73 74 5f 6c 6f 67 2e 74 78 74 } //1 svchost_log.txt
		$a_81_5 = {49 6d 70 6f 72 74 61 6e 74 20 66 69 6c 65 73 20 65 6e 63 72 79 70 74 65 64 2e 20 43 68 65 63 6b 20 52 45 41 44 4d 45 20 66 69 6c 65 73 } //1 Important files encrypted. Check README files
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}