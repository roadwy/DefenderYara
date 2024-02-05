
rule Trojan_Linux_BuhtiRansom_A{
	meta:
		description = "Trojan:Linux/BuhtiRansom.A,SIGNATURE_TYPE_ELFHSTR_EXT,07 00 07 00 05 00 00 05 00 "
		
	strings :
		$a_80_0 = {57 65 6c 63 6f 6d 65 20 74 6f 20 62 75 68 74 69 52 61 6e 73 6f 6d } //Welcome to buhtiRansom  01 00 
		$a_80_1 = {59 6f 75 72 20 66 69 6c 65 73 20 61 72 65 20 65 6e 63 72 79 70 74 65 64 } //Your files are encrypted  01 00 
		$a_80_2 = {50 61 79 20 61 6d 6f 75 6e 74 20 74 6f 20 42 69 74 63 6f 69 6e 20 61 64 64 72 65 73 73 } //Pay amount to Bitcoin address  01 00 
		$a_80_3 = {44 65 63 72 79 70 74 20 69 6e 73 74 72 75 63 74 69 6f 6e 20 69 6e 63 6c 75 64 65 64 } //Decrypt instruction included  01 00 
		$a_80_4 = {6d 61 69 6e 2e 65 6e 63 72 79 70 74 5f 66 69 6c 65 } //main.encrypt_file  00 00 
	condition:
		any of ($a_*)
 
}