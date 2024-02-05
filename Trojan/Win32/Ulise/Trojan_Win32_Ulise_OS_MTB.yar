
rule Trojan_Win32_Ulise_OS_MTB{
	meta:
		description = "Trojan:Win32/Ulise.OS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {8a 14 4e 84 d2 75 0a 38 54 4e 01 74 0c 3b cb 7d 08 f6 d2 88 14 01 41 eb e7 c6 04 01 00 66 39 7c 4e 02 5f 5e 5b } //01 00 
		$a_01_1 = {43 68 61 6e 67 65 53 65 72 76 69 63 65 43 6f 6e 66 69 67 32 41 } //01 00 
		$a_01_2 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //00 00 
	condition:
		any of ($a_*)
 
}