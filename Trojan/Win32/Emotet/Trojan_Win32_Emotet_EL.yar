
rule Trojan_Win32_Emotet_EL{
	meta:
		description = "Trojan:Win32/Emotet.EL,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 05 00 "
		
	strings :
		$a_01_0 = {59 75 6d 44 57 50 2e 70 64 62 } //01 00  YumDWP.pdb
		$a_01_1 = {73 00 43 00 32 00 77 00 45 00 40 00 51 00 65 00 50 00 25 00 44 00 } //05 00  sC2wE@QeP%D
		$a_01_2 = {74 6b 57 53 75 2e 70 64 62 } //01 00  tkWSu.pdb
		$a_01_3 = {4f 00 72 00 69 00 67 00 69 00 6e 00 61 00 6c 00 46 00 69 00 6c 00 65 00 6e 00 61 00 6d 00 65 00 00 00 42 00 69 00 74 00 73 00 50 00 65 00 72 00 66 00 2e 00 64 00 6c 00 00 00 00 } //00 00 
		$a_00_4 = {5d 04 00 00 44 } //cf 03 
	condition:
		any of ($a_*)
 
}