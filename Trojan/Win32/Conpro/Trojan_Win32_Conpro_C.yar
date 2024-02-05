
rule Trojan_Win32_Conpro_C{
	meta:
		description = "Trojan:Win32/Conpro.C,SIGNATURE_TYPE_PEHSTR_EXT,07 00 05 00 05 00 00 04 00 "
		
	strings :
		$a_03_0 = {83 c0 9e 83 f8 16 0f 87 90 01 02 00 00 33 c9 8a 88 90 01 04 ff 24 8d 90 01 04 8b 54 24 90 01 01 52 e8 90 00 } //01 00 
		$a_00_1 = {62 3a 6d 3a 78 3a 75 3a } //01 00 
		$a_00_2 = {43 4f 4e 4e 45 43 54 20 25 73 3a 25 64 20 48 54 54 50 2f 31 2e 30 } //01 00 
		$a_00_3 = {72 63 78 2e 74 78 74 00 } //01 00 
		$a_00_4 = {6e 6f 20 63 6f 6e 66 69 67 75 72 65 21 } //00 00 
	condition:
		any of ($a_*)
 
}