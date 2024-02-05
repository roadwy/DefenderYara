
rule Trojan_Win32_Ninject_RA_MTB{
	meta:
		description = "Trojan:Win32/Ninject.RA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {50 65 6e 74 79 6c 65 6e 65 74 65 74 72 61 7a 6f 6c 2e 64 6c 6c } //01 00 
		$a_01_1 = {41 66 64 65 6c 69 6e 67 73 6b 6f 6e 66 65 72 65 6e 63 65 2e 69 6e 69 } //01 00 
		$a_01_2 = {4b 75 72 73 75 73 6c 65 64 65 6c 73 65 6e 2e 69 6e 69 } //01 00 
		$a_01_3 = {53 6f 66 74 77 61 72 65 5c 46 61 64 64 65 72 65 6e 73 } //01 00 
		$a_01_4 = {48 79 61 6c 6f 70 68 61 6e 65 2e 69 6e 69 } //00 00 
	condition:
		any of ($a_*)
 
}