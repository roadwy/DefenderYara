
rule Ransom_Win32_Sage_AA_MTB{
	meta:
		description = "Ransom:Win32/Sage.AA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 03 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 61 67 65 20 65 6e 63 72 79 70 74 65 } //01 00  Sage encrypte
		$a_01_1 = {41 6c 6c 20 79 6f 75 72 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 20 77 69 74 68 20 74 68 65 20 70 75 62 6c 69 63 20 6b 65 79 } //01 00  All your files have been encrypted with the public key
		$a_00_2 = {64 00 65 00 6c 00 65 00 74 00 65 00 20 00 73 00 68 00 61 00 64 00 6f 00 77 00 73 00 20 00 2f 00 61 00 6c 00 6c 00 20 00 2f 00 71 00 75 00 69 00 65 00 74 00 } //01 00  delete shadows /all /quiet
		$a_01_3 = {21 52 65 63 6f 76 65 72 79 5f 25 73 2e 74 78 74 } //01 00  !Recovery_%s.txt
		$a_01_4 = {21 52 65 63 6f 76 65 72 79 5f 25 73 2e 68 74 6d 6c } //00 00  !Recovery_%s.html
	condition:
		any of ($a_*)
 
}