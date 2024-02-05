
rule Trojan_Win32_Tarifarch_O{
	meta:
		description = "Trojan:Win32/Tarifarch.O,SIGNATURE_TYPE_PEHSTR,03 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {6d 8c 2d c6 5c a3 b9 bd 1d 3b 83 e6 74 27 35 3d 07 a7 cb 56 19 be 18 d4 ca 9e 59 53 90 8b 14 0e } //01 00 
		$a_01_1 = {62 00 69 00 6c 00 6c 00 2f 00 72 00 75 00 6c 00 } //01 00 
		$a_01_2 = {3a 00 2f 00 2f 00 68 00 65 00 6c 00 70 00 70 00 72 00 69 00 63 00 65 00 2e 00 69 00 } //00 00 
	condition:
		any of ($a_*)
 
}