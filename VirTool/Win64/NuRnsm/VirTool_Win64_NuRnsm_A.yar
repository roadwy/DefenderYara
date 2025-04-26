
rule VirTool_Win64_NuRnsm_A{
	meta:
		description = "VirTool:Win64/NuRnsm.A,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 05 00 00 "
		
	strings :
		$a_01_0 = {44 65 63 72 79 70 74 20 69 6e 73 74 65 61 64 20 6f 66 20 65 6e 63 72 79 70 74 69 6e 67 } //2 Decrypt instead of encrypting
		$a_01_1 = {52 65 61 64 2f 77 72 69 74 65 20 41 45 53 20 6b 65 79 20 66 72 6f 6d 2f 74 6f 20 5b 66 69 6c 65 5d 20 6f 72 20 64 6f 77 6e 6c 6f 61 64 2f 75 70 6c 6f 61 64 20 66 72 6f 6d 2f 74 6f 20 5b 75 72 6c 5d } //2 Read/write AES key from/to [file] or download/upload from/to [url]
		$a_01_2 = {46 6f 6c 64 65 72 28 73 29 20 74 6f 20 72 65 63 75 72 73 69 76 65 6c 79 20 65 6e 63 72 79 70 74 20 6f 72 20 64 65 63 72 79 70 74 } //2 Folder(s) to recursively encrypt or decrypt
		$a_01_3 = {66 69 6c 65 7c 75 72 6c } //2 file|url
		$a_01_4 = {6b 65 79 2d 66 69 6c 65 } //2 key-file
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2) >=10
 
}