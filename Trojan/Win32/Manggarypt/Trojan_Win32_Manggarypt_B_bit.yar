
rule Trojan_Win32_Manggarypt_B_bit{
	meta:
		description = "Trojan:Win32/Manggarypt.B!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b c7 8d 0c 37 99 f7 7d 90 01 01 8a 44 15 90 01 01 32 04 19 88 01 90 00 } //01 00 
		$a_03_1 = {3d 00 00 00 80 73 90 01 01 83 c0 02 03 c3 eb 90 01 01 0f b7 c0 50 ff 75 90 01 01 ff 15 90 01 04 89 04 37 83 c6 04 8b 06 90 00 } //01 00 
		$a_03_2 = {8a 11 8d 42 90 01 01 3c 19 77 03 80 c2 e0 88 11 41 80 39 00 75 ec 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}