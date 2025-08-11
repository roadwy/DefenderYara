
rule Ransom_Win64_FileCoder_AYG_MTB{
	meta:
		description = "Ransom:Win64/FileCoder.AYG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_01_0 = {54 68 69 73 20 49 53 20 72 65 61 6c 20 72 61 6e 73 6f 6d 77 61 72 65 2e 20 41 72 65 20 79 6f 75 20 73 75 72 65 20 79 6f 75 20 77 61 6e 74 20 74 6f 20 72 75 6e 20 69 74 3f } //2 This IS real ransomware. Are you sure you want to run it?
		$a_01_1 = {44 6f 20 6e 6f 74 20 63 6c 6f 73 65 20 74 68 65 20 77 69 6e 64 6f 77 20 6f 72 20 69 74 20 63 6f 75 6c 64 20 6c 65 61 64 20 74 6f 20 64 61 74 61 20 6c 6f 73 73 21 } //1 Do not close the window or it could lead to data loss!
		$a_01_2 = {65 6e 63 72 79 70 74 65 64 5f 66 69 6c 65 73 2e 74 78 74 } //1 encrypted_files.txt
		$a_01_3 = {61 61 61 5f 54 6f 75 63 68 4d 65 4e 6f 74 5f 2e 74 78 74 } //1 aaa_TouchMeNot_.txt
		$a_01_4 = {53 6f 66 74 77 61 72 65 5c 43 6c 61 73 73 65 73 5c 2e 78 63 72 79 70 74 5c 44 65 66 61 75 6c 74 49 63 6f 6e } //1 Software\Classes\.xcrypt\DefaultIcon
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=6
 
}