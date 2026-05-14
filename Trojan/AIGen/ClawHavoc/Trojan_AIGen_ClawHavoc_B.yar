
rule Trojan_AIGen_ClawHavoc_B{
	meta:
		description = "Trojan:AIGen/ClawHavoc.B,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_00_0 = {53 00 65 00 74 00 75 00 70 00 2d 00 57 00 69 00 7a 00 61 00 72 00 64 00 } //1 Setup-Wizard
		$a_00_1 = {49 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 65 00 72 00 2d 00 50 00 61 00 63 00 6b 00 61 00 67 00 65 00 } //1 Installer-Package
		$a_00_2 = {65 00 63 00 68 00 6f 00 90 00 02 00 ff 00 62 00 61 00 73 00 65 00 36 00 34 00 20 00 2d 00 44 00 90 00 00 00 } //1
		$a_00_3 = {62 00 61 00 73 00 68 00 } //1 bash
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=3
 
}