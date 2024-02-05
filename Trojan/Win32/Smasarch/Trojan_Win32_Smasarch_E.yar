
rule Trojan_Win32_Smasarch_E{
	meta:
		description = "Trojan:Win32/Smasarch.E,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {24 7b 54 58 54 5f 4d 45 53 53 41 47 45 53 4f 4e 45 7d } //01 00 
		$a_01_1 = {24 7b 54 58 54 5f 4d 45 53 53 41 47 45 53 5f 41 55 53 54 52 41 4c 49 41 7d } //01 00 
		$a_01_2 = {73 65 74 74 20 6d 69 6e 20 68 6a 65 6d 6d 65 73 69 64 65 20 74 69 6c 20 57 6f 6f 66 69 20 76 65 72 6b 74 } //01 00 
		$a_01_3 = {34 30 20 4b 72 6f 6e 65 72 2f 73 6d 73 2e } //01 00 
		$a_01_4 = {70 61 6e 74 61 6c 6c 61 63 6f 64 69 67 6f } //00 00 
	condition:
		any of ($a_*)
 
}