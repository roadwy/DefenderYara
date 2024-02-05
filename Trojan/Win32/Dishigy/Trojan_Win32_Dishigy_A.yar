
rule Trojan_Win32_Dishigy_A{
	meta:
		description = "Trojan:Win32/Dishigy.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {66 b8 24 00 e8 90 01 04 8b 55 ec 90 00 } //01 00 
		$a_03_1 = {b8 e7 03 00 00 e8 90 01 04 8d 55 d8 90 00 } //01 00 
		$a_03_2 = {c7 80 c8 01 00 00 db 05 00 00 8b 45 f8 83 c0 34 ba 90 01 04 e8 90 01 04 b8 75 00 00 00 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}