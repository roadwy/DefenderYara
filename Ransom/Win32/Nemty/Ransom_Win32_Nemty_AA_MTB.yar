
rule Ransom_Win32_Nemty_AA_MTB{
	meta:
		description = "Ransom:Win32/Nemty.AA!MTB,SIGNATURE_TYPE_PEHSTR,22 00 22 00 06 00 00 0a 00 "
		
	strings :
		$a_01_0 = {4e 45 4d 54 59 } //0a 00  NEMTY
		$a_01_1 = {44 00 45 00 43 00 52 00 59 00 50 00 54 00 2e 00 74 00 78 00 74 00 } //0a 00  DECRYPT.txt
		$a_01_2 = {59 6f 75 72 20 66 69 6c 65 73 20 77 65 72 65 20 65 6e 63 72 79 70 74 65 64 21 } //02 00  Your files were encrypted!
		$a_01_3 = {25 63 6f 6d 70 6e 61 6d 65 25 } //02 00  %compname%
		$a_01_4 = {25 66 69 6c 65 69 64 25 } //02 00  %fileid%
		$a_01_5 = {25 75 73 65 72 6e 61 6d 65 25 } //00 00  %username%
		$a_01_6 = {00 5d 04 00 00 3f 22 04 80 5c 26 00 } //00 40 
	condition:
		any of ($a_*)
 
}