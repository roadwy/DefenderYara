
rule Trojan_Win32_Dedreftot_A{
	meta:
		description = "Trojan:Win32/Dedreftot.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {74 0d c0 08 02 80 30 90 01 01 40 49 83 f9 00 90 00 } //01 00 
		$a_01_1 = {ff d5 8d 87 9f 01 00 00 80 20 7f 80 60 28 7f } //01 00 
		$a_01_2 = {8b 14 24 8b 52 3c 8b c3 03 d0 81 c2 f8 00 00 00 0f b7 cf c1 e1 03 8d 0c 89 03 d1 } //00 00 
	condition:
		any of ($a_*)
 
}