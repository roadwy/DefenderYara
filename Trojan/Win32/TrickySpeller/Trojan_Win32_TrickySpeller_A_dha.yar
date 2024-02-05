
rule Trojan_Win32_TrickySpeller_A_dha{
	meta:
		description = "Trojan:Win32/TrickySpeller.A!dha,SIGNATURE_TYPE_CMDHSTR_EXT,63 00 0b 00 02 00 00 0a 00 "
		
	strings :
		$a_00_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //01 00 
		$a_00_1 = {24 00 74 00 20 00 3d 00 20 00 27 00 27 00 3b 00 66 00 6f 00 72 00 28 00 24 00 69 00 3d 00 30 00 3b 00 24 00 69 00 20 00 2d 00 6c 00 74 00 20 00 24 00 61 00 2e 00 4c 00 65 00 6e 00 67 00 74 00 68 00 3b 00 24 00 69 00 2b 00 3d 00 33 00 29 00 } //00 00 
	condition:
		any of ($a_*)
 
}