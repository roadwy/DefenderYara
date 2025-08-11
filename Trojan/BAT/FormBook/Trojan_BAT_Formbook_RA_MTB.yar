
rule Trojan_BAT_Formbook_RA_MTB{
	meta:
		description = "Trojan:BAT/Formbook.RA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {4d 65 63 68 4d 61 74 72 69 78 20 50 72 6f 2e 64 6c 6c } //1 MechMatrix Pro.dll
		$a_81_1 = {6e 6f 74 65 70 61 64 2e 72 74 66 } //1 notepad.rtf
		$a_81_2 = {42 6c 61 68 20 62 6c 61 68 20 62 6c 61 68 } //1 Blah blah blah
		$a_81_3 = {50 68 61 6e 74 6f 6d 20 44 69 6d 65 6e 73 69 6f 6e 20 53 6f 66 74 77 61 72 65 } //1 Phantom Dimension Software
	condition:
		((#a_01_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}