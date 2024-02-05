
rule Trojan_Win32_NSISInject_RPM_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.RPM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_81_0 = {41 6e 6c 67 73 69 6e 76 65 73 74 65 72 69 6e 67 65 72 2e 4d 69 6e } //01 00 
		$a_81_1 = {41 62 65 6c 73 6b 2e 48 75 6d } //01 00 
		$a_81_2 = {53 6f 66 74 77 61 72 65 5c 43 68 6f 6c 65 63 79 73 74 65 63 74 61 73 69 61 38 39 5c 50 65 70 79 73 69 61 6e 5c 4e 6f 6e 70 65 73 74 69 6c 65 6e 74 6c 79 } //01 00 
		$a_81_3 = {53 61 6d 6c 65 6f 62 6a 65 6b 74 73 2e 69 6e 69 } //01 00 
		$a_81_4 = {49 6e 64 65 62 74 2e 42 65 73 } //00 00 
	condition:
		any of ($a_*)
 
}