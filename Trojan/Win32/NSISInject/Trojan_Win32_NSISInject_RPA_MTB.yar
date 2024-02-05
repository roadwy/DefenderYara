
rule Trojan_Win32_NSISInject_RPA_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.RPA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 74 72 69 6b 6b 65 74 6a 65 74 } //01 00 
		$a_01_1 = {42 6f 74 74 6f 6d 65 72 2e 43 61 78 32 32 38 } //01 00 
		$a_01_2 = {44 79 62 66 72 6f 73 73 65 6e 2e 69 6e 69 } //01 00 
		$a_01_3 = {62 65 6e 65 66 69 63 69 6e 67 5c 47 61 6c 61 68 61 64 73 2e 53 75 6e } //01 00 
		$a_01_4 = {53 6f 63 69 61 6c 61 72 62 65 6a 64 65 2e 69 6e 69 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_NSISInject_RPA_MTB_2{
	meta:
		description = "Trojan:Win32/NSISInject.RPA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_81_0 = {63 61 72 61 76 61 6e 65 72 73 } //01 00 
		$a_81_1 = {55 6e 6e 6f 74 69 6f 6e 65 64 2e 62 6d 70 } //01 00 
		$a_81_2 = {42 6c 61 61 6c 69 67 74 } //01 00 
		$a_81_3 = {53 63 68 6f 72 6c 6f 6d 69 74 65 39 39 } //01 00 
		$a_81_4 = {53 6f 66 74 77 61 72 65 5c 42 69 66 75 72 63 61 74 69 6f 6e 5c 57 65 6e 64 65 64 5c 4f 75 74 63 61 73 74 65 73 } //00 00 
	condition:
		any of ($a_*)
 
}