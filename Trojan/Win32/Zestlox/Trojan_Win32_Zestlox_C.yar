
rule Trojan_Win32_Zestlox_C{
	meta:
		description = "Trojan:Win32/Zestlox.C,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 6a 6f 62 31 32 33 } //01 00 
		$a_01_1 = {2e 63 6e 2f 69 6e 73 73 2f 4e 65 77 56 65 72 } //01 00 
		$a_01_2 = {53 76 63 68 6f 73 74 45 6e 74 72 79 5f 57 33 32 54 69 6d 65 } //01 00 
		$a_01_3 = {48 4b 45 59 5f 4c 4f 43 41 4c 5f 4d 41 43 48 49 4e 45 5c 53 59 53 54 45 4d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 53 65 72 76 69 63 65 73 5c 57 33 32 54 69 6d 65 } //00 00 
	condition:
		any of ($a_*)
 
}