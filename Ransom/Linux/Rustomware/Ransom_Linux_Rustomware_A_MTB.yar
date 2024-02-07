
rule Ransom_Linux_Rustomware_A_MTB{
	meta:
		description = "Ransom:Linux/Rustomware.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {52 45 41 44 4d 45 5f 52 75 73 74 73 6f 6d 77 61 72 65 } //02 00  README_Rustsomware
		$a_01_1 = {72 75 73 74 73 6f 6d 77 61 72 65 20 3c 65 6e 63 72 79 70 74 } //01 00  rustsomware <encrypt
		$a_01_2 = {44 72 6f 70 70 65 64 20 72 61 6e 73 6f 6d 20 6d 65 73 73 61 67 65 } //01 00  Dropped ransom message
		$a_01_3 = {75 6e 77 69 6e 64 5f 67 65 74 74 65 78 74 72 65 6c 62 61 73 65 } //00 00  unwind_gettextrelbase
	condition:
		any of ($a_*)
 
}