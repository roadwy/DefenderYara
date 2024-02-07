
rule Trojan_Win32_Gutosver_A{
	meta:
		description = "Trojan:Win32/Gutosver.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {2e aa c6 44 24 90 01 01 63 c6 44 24 90 01 01 6f c7 44 24 20 01 00 00 00 c6 44 24 90 01 01 6d 0f 85 90 00 } //01 00 
		$a_03_1 = {30 40 00 6a 02 68 90 01 04 ff 90 04 01 02 d6 d7 8b ce e8 90 01 02 00 00 8b 15 90 01 04 a1 90 01 04 89 54 24 28 8b 15 90 01 04 89 54 24 2c 8b 15 90 01 04 89 54 24 30 90 00 } //00 00 
		$a_00_2 = {5d } //04 00  ]
	condition:
		any of ($a_*)
 
}