
rule Trojan_Win32_Bangsmoop_A{
	meta:
		description = "Trojan:Win32/Bangsmoop.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {b9 00 20 00 00 66 09 48 16 } //01 00 
		$a_01_1 = {b8 00 20 00 00 66 09 46 16 } //01 00 
		$a_03_2 = {83 c4 0c 80 90 01 01 e9 75 90 00 } //01 00 
		$a_03_3 = {d8 f5 01 00 25 ff 00 00 0f 94 c1 90 09 04 00 33 c9 81 90 00 } //01 00 
		$a_03_4 = {83 f8 66 74 90 01 01 83 f8 6b 90 00 } //01 00 
		$a_03_5 = {0f b7 47 14 90 02 02 8d 74 38 18 6a 28 56 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}