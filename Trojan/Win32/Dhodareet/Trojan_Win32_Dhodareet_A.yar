
rule Trojan_Win32_Dhodareet_A{
	meta:
		description = "Trojan:Win32/Dhodareet.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {b0 65 c6 06 61 c6 46 01 76 c6 46 02 67 c6 46 03 73 c6 46 04 63 c6 46 05 61 c6 46 06 6e 88 4e 07 c6 46 08 2e 88 46 09 } //01 00 
		$a_01_1 = {3d 00 00 ff 7f 77 29 68 e9 00 00 00 53 e8 } //01 00 
		$a_01_2 = {8b 7b 14 80 3f e9 75 7b 8b 4b 18 b8 90 90 90 90 } //01 00 
		$a_01_3 = {3d 85 de 23 00 75 0d } //00 00 
	condition:
		any of ($a_*)
 
}