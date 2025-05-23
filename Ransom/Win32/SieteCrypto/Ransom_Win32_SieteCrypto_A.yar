
rule Ransom_Win32_SieteCrypto_A{
	meta:
		description = "Ransom:Win32/SieteCrypto.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 08 00 00 "
		
	strings :
		$a_03_0 = {25 73 2e 5f 25 30 32 69 2d 25 30 32 69 2d 25 30 32 69 2d 25 30 32 69 2d 25 30 32 69 2d 25 30 32 69 5f 24 25 73 24 2e ?? ?? ?? 00 } //1
		$a_01_1 = {25 73 3f 69 70 3d 25 73 00 } //1
		$a_01_2 = {40 00 53 00 79 00 73 00 74 00 65 00 6d 00 20 00 65 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 00 00 } //1
		$a_01_3 = {45 00 6e 00 63 00 72 00 79 00 70 00 74 00 6f 00 72 00 00 00 } //1
		$a_01_4 = {50 00 72 00 65 00 73 00 73 00 20 00 4f 00 4b 00 20 00 74 00 6f 00 20 00 65 00 6e 00 63 00 72 00 79 00 70 00 74 00 00 00 } //1
		$a_01_5 = {44 00 65 00 6d 00 6f 00 20 00 76 00 65 00 72 00 73 00 69 00 6f 00 6e 00 20 00 77 00 6f 00 72 00 6b 00 73 00 20 00 74 00 69 00 6c 00 6c 00 } //1 Demo version works till
		$a_01_6 = {5c 00 72 00 65 00 61 00 64 00 5f 00 74 00 68 00 69 00 73 00 5f 00 66 00 69 00 6c 00 65 00 2e 00 74 00 78 00 74 00 } //1 \read_this_file.txt
		$a_01_7 = {37 00 5c 00 74 00 6d 00 70 00 2e 00 62 00 6d 00 70 00 00 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=5
 
}