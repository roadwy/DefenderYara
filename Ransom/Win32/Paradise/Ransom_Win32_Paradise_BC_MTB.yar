
rule Ransom_Win32_Paradise_BC_MTB{
	meta:
		description = "Ransom:Win32/Paradise.BC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_80_0 = {44 6f 20 6e 6f 74 20 74 72 79 20 74 6f 20 64 65 63 72 79 70 74 } //Do not try to decrypt  1
		$a_80_1 = {44 69 73 61 62 6c 65 41 6e 74 69 53 70 79 77 61 72 65 } //DisableAntiSpyware  1
		$a_80_2 = {64 65 6c 65 74 65 20 73 68 61 64 6f 77 73 20 2f 61 6c 6c 20 2f 71 75 69 65 74 } //delete shadows /all /quiet  1
		$a_80_3 = {44 6f 20 6e 6f 74 20 72 65 6e 61 6d 65 20 65 6e 63 72 79 70 74 65 64 20 66 69 6c 65 73 } //Do not rename encrypted files  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=3
 
}