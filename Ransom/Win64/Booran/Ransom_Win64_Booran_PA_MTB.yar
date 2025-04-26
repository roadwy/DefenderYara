
rule Ransom_Win64_Booran_PA_MTB{
	meta:
		description = "Ransom:Win64/Booran.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {48 45 4c 4c 4f 5f 52 45 41 44 4d 45 2e 74 78 74 } //1 HELLO_README.txt
		$a_01_1 = {21 21 21 20 44 41 4e 47 45 52 20 21 21 21 } //1 !!! DANGER !!!
		$a_01_2 = {5c 5c 2e 5c 70 69 70 65 5c 5f 5f 72 75 73 74 5f 61 6e 6f 6e 79 6d 6f 75 73 5f 70 69 70 65 31 5f 5f } //1 \\.\pipe\__rust_anonymous_pipe1__
		$a_01_3 = {59 6f 75 72 20 66 69 6c 65 73 20 61 72 65 20 65 6e 63 72 79 70 74 65 64 2c 20 61 6e 64 20 63 75 72 72 65 6e 74 6c 79 20 75 6e 61 76 61 69 6c 61 62 6c 65 2e } //1 Your files are encrypted, and currently unavailable.
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}