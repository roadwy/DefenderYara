
rule Trojan_Win32_Smasarch_AO_bit{
	meta:
		description = "Trojan:Win32/Smasarch.AO!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {48 4b 43 55 5c 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //01 00 
		$a_01_1 = {64 75 63 6b 64 6e 73 2e 6f 72 67 00 53 62 69 65 44 6c 6c } //01 00 
		$a_01_2 = {63 61 70 74 75 72 61 2e 62 6d 70 } //00 00 
	condition:
		any of ($a_*)
 
}