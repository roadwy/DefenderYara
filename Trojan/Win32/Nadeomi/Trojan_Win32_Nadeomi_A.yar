
rule Trojan_Win32_Nadeomi_A{
	meta:
		description = "Trojan:Win32/Nadeomi.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {00 5c 6d 69 6e 65 72 5c 73 74 61 72 74 2e 62 61 74 00 } //01 00 
		$a_01_1 = {5c 77 69 6e 63 68 65 63 6b 2e 76 62 73 } //01 00  \wincheck.vbs
		$a_01_2 = {00 44 72 6f 70 65 72 44 65 6d 6f 00 } //01 00  䐀潲数䑲浥o
		$a_00_3 = {6f 45 6e 76 28 22 53 45 45 5f 4d 41 53 4b 5f 4e 4f 5a 4f 4e 45 43 48 45 43 4b 53 22 29 20 3d 20 31 } //00 00  oEnv("SEE_MASK_NOZONECHECKS") = 1
	condition:
		any of ($a_*)
 
}