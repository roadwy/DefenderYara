
rule Trojan_Win32_Aydamine_A{
	meta:
		description = "Trojan:Win32/Aydamine.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 79 73 2d 4d 75 74 65 78 32 } //01 00 
		$a_01_1 = {5c 72 65 67 69 73 74 72 61 74 69 6f 6e 5c 72 65 67 2e 63 6e 66 } //01 00 
		$a_01_2 = {5c 53 79 73 44 61 74 61 5c 61 63 6e 6f 6d 2e 65 78 65 } //01 00 
		$a_01_3 = {5c 53 79 73 44 61 74 61 5c 61 63 6e 6f 6e 2e 65 78 65 } //01 00 
		$a_01_4 = {2d 63 20 31 20 2d 4d 20 73 74 72 61 74 75 6d 2b 74 63 70 3a 2f 2f } //00 00 
	condition:
		any of ($a_*)
 
}