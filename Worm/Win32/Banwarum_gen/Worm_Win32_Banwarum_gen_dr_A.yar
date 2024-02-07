
rule Worm_Win32_Banwarum_gen_dr_A{
	meta:
		description = "Worm:Win32/Banwarum_gen!dr.A,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0b 00 06 00 00 04 00 "
		
	strings :
		$a_00_0 = {68 6c 65 67 65 68 72 69 76 69 68 62 75 67 50 68 53 65 44 65 } //04 00  hlegehrivihbugPhSeDe
		$a_00_1 = {68 2e 65 78 65 68 6f 67 6f 6e 68 77 69 6e 6c } //04 00  h.exehogonhwinl
		$a_01_2 = {4f 70 65 6e 50 72 6f 63 65 73 73 54 6f 6b 65 6e 00 57 69 6e 33 32 2e 5a } //02 00  灏湥牐捯獥味歯湥圀湩㈳娮
		$a_00_3 = {74 5b 50 6a 00 68 ff 0f 1f 00 ff 15 } //02 00 
		$a_00_4 = {74 49 89 c7 6a 40 68 00 30 00 00 68 00 01 00 00 6a 00 57 ff 15 } //01 00 
		$a_00_5 = {00 00 50 00 02 00 00 00 04 00 0f 00 ff ff 00 00 b8 } //00 00 
	condition:
		any of ($a_*)
 
}