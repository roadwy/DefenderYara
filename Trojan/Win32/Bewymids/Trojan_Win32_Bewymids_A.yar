
rule Trojan_Win32_Bewymids_A{
	meta:
		description = "Trojan:Win32/Bewymids.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {74 18 6a 02 6a 98 57 e8 90 01 04 83 c4 0c 85 c0 74 0b 90 00 } //01 00 
		$a_03_1 = {80 3b 63 8b f8 0f 85 90 01 02 00 00 80 7b 01 64 0f 85 90 01 02 00 00 80 7b 02 20 0f 85 90 00 } //01 00 
		$a_01_2 = {8a 14 08 02 d0 80 c2 5a 32 d0 88 14 08 40 3b 44 24 08 7c ec } //00 00 
	condition:
		any of ($a_*)
 
}