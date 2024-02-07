
rule Trojan_Win32_Tamgitel_A{
	meta:
		description = "Trojan:Win32/Tamgitel.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {33 c9 66 b9 90 02 05 80 34 11 04 90 02 05 e2 90 00 } //01 00 
		$a_01_1 = {c7 60 a5 34 04 04 04 81 c4 7c } //01 00 
		$a_03_2 = {57 37 df 52 c2 41 90 01 01 45 c2 41 90 01 01 67 c2 41 90 01 01 68 c2 41 90 01 01 51 90 00 } //00 00 
		$a_00_3 = {5d 04 } //00 00  ѝ
	condition:
		any of ($a_*)
 
}