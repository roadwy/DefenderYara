
rule Ransom_Win32_Crypren_PAGK_MTB{
	meta:
		description = "Ransom:Win32/Crypren.PAGK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 05 00 00 "
		
	strings :
		$a_01_0 = {46 61 69 6c 65 64 20 74 6f 20 6f 70 65 6e 20 66 69 6c 65 20 66 6f 72 20 65 6e 63 72 79 70 74 69 6f 6e 3a 20 25 73 } //2 Failed to open file for encryption: %s
		$a_01_1 = {46 61 69 6c 65 64 20 74 6f 20 72 65 61 64 20 66 69 6c 65 3a 20 25 73 } //1 Failed to read file: %s
		$a_01_2 = {46 61 69 6c 65 64 20 74 6f 20 77 72 69 74 65 20 74 6f 20 66 69 6c 65 3a 20 25 73 } //1 Failed to write to file: %s
		$a_01_3 = {25 73 2e 6c 6f 63 6b 65 64 } //2 %s.locked
		$a_01_4 = {45 6e 63 72 79 70 74 65 64 20 61 6e 64 20 72 65 6e 61 6d 65 64 20 66 69 6c 65 3a 20 25 73 20 2d 3e 20 25 73 } //2 Encrypted and renamed file: %s -> %s
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2) >=8
 
}