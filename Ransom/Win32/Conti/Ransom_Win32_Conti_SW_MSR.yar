
rule Ransom_Win32_Conti_SW_MSR{
	meta:
		description = "Ransom:Win32/Conti.SW!MSR,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_80_0 = {54 68 65 20 6e 65 74 77 6f 72 6b 20 69 73 20 4c 4f 43 4b 45 44 } //The network is LOCKED  1
		$a_80_1 = {44 6f 20 6e 6f 74 20 74 72 79 20 74 6f 20 75 73 65 20 6f 74 68 65 72 20 73 6f 66 74 77 61 72 65 2e 20 46 6f 72 20 64 65 63 72 79 70 74 69 6f 6e 20 4b 45 59 20 77 72 69 74 65 20 48 45 52 45 } //Do not try to use other software. For decryption KEY write HERE  1
		$a_80_2 = {66 6c 61 70 61 6c 69 6e 74 61 31 39 35 30 40 70 72 6f 74 6f 6e 6d 61 69 6c 2e 63 6f 6d } //flapalinta1950@protonmail.com  1
		$a_80_3 = {78 65 72 73 61 6d 69 40 70 72 6f 74 6f 6e 6d 61 69 6c 2e 63 6f 6d } //xersami@protonmail.com  1
		$a_80_4 = {48 4f 57 5f 54 4f 5f 44 45 43 52 59 50 54 } //HOW_TO_DECRYPT  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=5
 
}