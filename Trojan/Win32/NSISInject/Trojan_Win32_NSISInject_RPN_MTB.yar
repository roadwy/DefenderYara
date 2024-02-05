
rule Trojan_Win32_NSISInject_RPN_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.RPN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {44 65 65 72 73 6b 69 6e } //01 00 
		$a_01_1 = {42 79 66 6f 72 6e 79 65 6c 73 65 72 6e 65 73 2e 46 6f 72 } //01 00 
		$a_01_2 = {53 6f 66 74 77 61 72 65 5c 4e 6f 6e 6f 6c 69 67 61 72 63 68 69 63 61 6c 5c 72 61 69 64 73 5c 54 72 69 6c 6c 69 6e 67 65 66 64 73 65 6c } //01 00 
		$a_01_3 = {54 72 61 76 65 74 75 72 65 73 2e 69 6e 69 } //01 00 
		$a_01_4 = {46 6c 75 69 64 75 6d 73 2e 69 6e 69 } //00 00 
	condition:
		any of ($a_*)
 
}