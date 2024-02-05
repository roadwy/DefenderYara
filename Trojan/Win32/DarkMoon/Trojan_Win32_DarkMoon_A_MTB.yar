
rule Trojan_Win32_DarkMoon_A_MTB{
	meta:
		description = "Trojan:Win32/DarkMoon.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_81_0 = {45 78 75 69 4b 72 6e 6c 6e 2e 64 6c 6c } //01 00 
		$a_81_1 = {45 78 75 69 4b 72 6e 6c 6e 2e 69 6e 69 } //01 00 
		$a_81_2 = {68 74 74 70 3a 2f 2f 6e 6f 74 65 2e 79 6f 75 64 61 6f 2e 63 6f 6d 2f 79 77 73 2f 61 70 69 2f 70 65 72 73 6f 6e 61 6c 2f 66 69 6c 65 2f 37 42 32 39 32 44 34 44 42 36 31 44 34 42 33 38 39 39 39 39 33 42 32 33 34 30 45 31 32 41 38 39 } //01 00 
		$a_81_3 = {42 6c 61 63 6b 4d 6f 6f 6e } //00 00 
	condition:
		any of ($a_*)
 
}