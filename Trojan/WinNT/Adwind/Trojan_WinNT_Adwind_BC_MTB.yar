
rule Trojan_WinNT_Adwind_BC_MTB{
	meta:
		description = "Trojan:WinNT/Adwind.BC!MTB,SIGNATURE_TYPE_JAVAHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {72 65 73 6f 75 72 63 65 73 2f 76 68 75 65 69 63 78 62 6b 62 } //01 00  resources/vhueicxbkb
		$a_00_1 = {61 70 62 79 77 6d 63 6b 78 6b 2f 4d 65 63 62 6c 61 7a 64 7a 64 75 } //01 00  apbywmckxk/Mecblazdzdu
		$a_00_2 = {67 65 6d 6f 64 67 6f 75 7a 6b 2e 76 62 73 } //00 00  gemodgouzk.vbs
	condition:
		any of ($a_*)
 
}