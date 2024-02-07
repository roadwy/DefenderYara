
rule Trojan_Win32_Cecapix_A{
	meta:
		description = "Trojan:Win32/Cecapix.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 06 00 00 02 00 "
		
	strings :
		$a_03_0 = {eb 34 53 ff 93 90 01 04 c1 e0 06 8d 84 18 90 01 04 50 ff b3 90 01 04 ff 93 90 00 } //02 00 
		$a_03_1 = {81 7d e4 9a 02 00 00 6a 05 50 50 8d 8b 90 01 04 74 06 90 00 } //01 00 
		$a_03_2 = {75 a6 eb 10 6a 00 6a 00 68 f5 00 00 00 57 ff 96 90 01 04 5e 90 00 } //01 00 
		$a_03_3 = {48 48 46 83 fe 08 7c c0 6a 22 68 90 01 04 6a 02 90 00 } //01 00 
		$a_00_4 = {74 00 61 00 73 00 6b 00 75 00 72 00 6c 00 } //01 00  taskurl
		$a_00_5 = {63 00 61 00 70 00 75 00 72 00 6c 00 } //00 00  capurl
	condition:
		any of ($a_*)
 
}