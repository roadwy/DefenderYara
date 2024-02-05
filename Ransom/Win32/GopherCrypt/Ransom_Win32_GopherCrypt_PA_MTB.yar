
rule Ransom_Win32_GopherCrypt_PA_MTB{
	meta:
		description = "Ransom:Win32/GopherCrypt.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_80_0 = {44 65 6c 65 74 65 20 53 68 61 64 6f 77 73 20 2f 41 6c 6c 20 2f 51 75 69 65 74 } //Delete Shadows /All /Quiet  01 00 
		$a_01_1 = {64 65 6c 65 74 65 20 63 61 74 61 6c 6f 67 20 2d 20 71 75 69 65 74 } //01 00 
		$a_01_2 = {2e 67 6f 70 68 65 72 } //01 00 
		$a_01_3 = {59 6f 75 20 68 61 76 65 20 62 65 65 6e 20 69 6e 66 65 63 74 65 64 20 62 79 20 74 68 65 20 42 61 64 20 47 6f 70 68 65 72 20 76 69 72 75 73 } //00 00 
	condition:
		any of ($a_*)
 
}