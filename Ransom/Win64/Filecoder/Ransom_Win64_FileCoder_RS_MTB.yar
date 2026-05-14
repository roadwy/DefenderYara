
rule Ransom_Win64_FileCoder_RS_MTB{
	meta:
		description = "Ransom:Win64/FileCoder.RS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {53 74 65 70 20 31 32 3a 20 46 69 6c 65 20 65 6e 63 72 79 70 74 69 6f 6e 20 63 6f 6d 70 6c 65 74 65 } //1 Step 12: File encryption complete
		$a_01_1 = {53 74 65 70 20 39 3a 20 47 65 74 74 69 6e 67 20 66 69 6c 65 20 70 61 74 68 73 2e 2e 2e } //1 Step 9: Getting file paths...
		$a_01_2 = {5b 2b 5d 20 57 61 6c 6b 69 6e 67 20 74 68 72 6f 75 67 68 20 64 69 72 65 63 74 6f 72 69 65 73 20 72 65 63 75 72 73 69 76 65 6c 79 } //1 [+] Walking through directories recursively
		$a_01_3 = {53 74 65 70 20 31 33 3a 20 53 65 6e 64 69 6e 67 20 64 61 74 61 20 74 6f 20 73 65 72 76 65 72 2e 2e } //1 Step 13: Sending data to server..
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}