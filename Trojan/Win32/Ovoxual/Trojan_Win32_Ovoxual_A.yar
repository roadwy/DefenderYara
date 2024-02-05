
rule Trojan_Win32_Ovoxual_A{
	meta:
		description = "Trojan:Win32/Ovoxual.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {c6 44 24 10 6f c6 44 24 15 78 } //01 00 
		$a_01_1 = {88 4c 24 14 88 5c 24 17 c6 44 24 0e 63 } //01 00 
		$a_01_2 = {b2 65 b0 6e b1 74 } //01 00 
		$a_01_3 = {8d 7c 24 20 f3 a5 66 81 7c 24 20 4d 5a } //01 00 
		$a_01_4 = {8d 54 24 10 51 8b 4c 24 3c 6a 04 83 c0 08 } //01 00 
		$a_01_5 = {8b 4c 24 48 3b c1 c7 44 24 54 07 00 01 00 } //00 00 
	condition:
		any of ($a_*)
 
}