
rule Trojan_Win32_Kuaibpy_A_bit{
	meta:
		description = "Trojan:Win32/Kuaibpy.A!bit,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {2e 6b 75 61 69 62 75 38 2e 63 } //01 00 
		$a_01_1 = {73 65 72 76 65 72 2e 74 78 74 } //01 00 
		$a_01_2 = {44 4c 4c 3a 70 63 2e 64 6c 6c } //01 00 
		$a_01_3 = {5c 54 43 50 2d 66 69 6c 65 2e 64 6c 6c } //01 00 
		$a_01_4 = {48 4b 45 59 5f 43 55 52 52 45 4e 54 5f 55 53 45 52 5c 62 75 67 } //00 00 
		$a_00_5 = {5d 04 00 } //00 fa 
	condition:
		any of ($a_*)
 
}