
rule Trojan_Win32_NSISInject_RPE_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.RPE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_81_0 = {32 30 2e 32 35 34 2e 35 33 2e 34 37 2f 62 72 75 6d 65 2e 70 68 70 } //01 00 
		$a_81_1 = {32 30 2e 32 33 34 2e 32 33 31 2e 31 31 34 2f 6d 78 2f 6a 35 37 62 35 67 39 73 38 74 72 35 38 63 77 6d 30 70 70 70 } //01 00 
		$a_81_2 = {70 69 66 65 61 69 7a 67 6a 63 2e 68 64 61 } //01 00 
		$a_81_3 = {65 36 37 34 34 62 34 36 6c 66 39 34 62 38 36 72 65 31 63 6f 6f 6f } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_NSISInject_RPE_MTB_2{
	meta:
		description = "Trojan:Win32/NSISInject.RPE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_81_0 = {45 6c 65 6b 74 72 6f 6e 69 6b 69 6e 64 75 73 74 72 69 65 6e } //01 00 
		$a_81_1 = {55 64 65 72 75 6d 6d 65 6e 65 73 2e 53 74 65 } //01 00 
		$a_81_2 = {4b 6f 6d 74 6f 6b 2e 4f 70 65 } //01 00 
		$a_81_3 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 55 6e 69 6e 73 74 61 6c 6c 5c 72 65 74 69 72 61 6e 74 5c 41 64 72 65 73 73 65 6c 69 73 74 65 6e } //01 00 
		$a_81_4 = {49 6e 64 74 61 67 6e 69 6e 67 65 6e 73 2e 55 6e 65 } //00 00 
	condition:
		any of ($a_*)
 
}