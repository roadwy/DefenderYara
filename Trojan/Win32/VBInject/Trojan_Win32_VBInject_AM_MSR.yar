
rule Trojan_Win32_VBInject_AM_MSR{
	meta:
		description = "Trojan:Win32/VBInject.AM!MSR,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 0b 00 00 01 00 "
		
	strings :
		$a_80_0 = {43 68 61 64 61 72 69 6d 38 } //Chadarim8  01 00 
		$a_80_1 = {49 6e 64 69 76 69 64 75 61 6c 73 32 } //Individuals2  01 00 
		$a_80_2 = {43 61 70 69 74 61 6c 69 7a 61 74 69 6f 6e } //Capitalization  01 00 
		$a_80_3 = {41 6d 62 69 74 69 6f 6e 65 64 30 } //Ambitioned0  01 00 
		$a_80_4 = {62 61 72 62 65 6c 73 } //barbels  01 00 
		$a_80_5 = {41 74 65 6c 69 65 72 73 38 } //Ateliers8  01 00 
		$a_80_6 = {41 77 6e 69 6e 67 65 64 33 } //Awninged3  01 00 
		$a_80_7 = {42 75 6e 64 6c 65 72 73 33 } //Bundlers3  01 00 
		$a_80_8 = {41 69 64 69 6e 67 } //Aiding  01 00 
		$a_80_9 = {48 65 61 64 73 74 72 6f 6e 67 } //Headstrong  01 00 
		$a_80_10 = {41 73 73 61 79 73 36 } //Assays6  00 00 
	condition:
		any of ($a_*)
 
}