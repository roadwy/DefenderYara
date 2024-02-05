
rule Trojan_Win32_BHO_AP{
	meta:
		description = "Trojan:Win32/BHO.AP,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {2e 64 6c 6c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 } //01 00 
		$a_02_1 = {5c 73 79 73 74 65 6d 33 32 5c 72 65 67 73 76 72 33 32 2e 65 78 65 20 61 64 73 6c 64 70 62 90 01 01 2e 64 6c 6c 20 2f 73 90 00 } //01 00 
		$a_02_2 = {5c 73 79 73 74 65 6d 33 32 5c 61 64 73 6c 64 70 62 90 01 01 2e 64 6c 6c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}