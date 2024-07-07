
rule Ransom_Win32_HiddenTear_GG_MTB{
	meta:
		description = "Ransom:Win32/HiddenTear.GG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_80_0 = {52 41 4e 53 4f 4d 57 41 52 45 } //RANSOMWARE  1
		$a_80_1 = {73 68 61 64 6f 77 63 6f 70 79 20 64 65 6c 65 74 65 } //shadowcopy delete  1
		$a_02_2 = {59 4f 55 52 90 02 04 46 49 4c 45 53 90 02 0f 45 4e 43 52 59 50 54 45 44 90 00 } //1
		$a_80_3 = {64 65 63 72 79 70 74 69 6f 6e } //decryption  1
		$a_80_4 = {42 69 74 63 6f 69 6e 20 61 64 64 72 65 73 73 } //Bitcoin address  1
		$a_80_5 = {62 75 79 20 62 69 74 63 6f 69 6e 73 } //buy bitcoins  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_02_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1) >=6
 
}