
rule Trojan_Win32_Alureon_GT{
	meta:
		description = "Trojan:Win32/Alureon.GT,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {68 3c 3c 22 00 56 89 5c 24 90 01 01 ff 15 90 01 04 56 ff 15 90 01 04 8d 84 24 90 01 02 00 00 50 68 02 00 00 80 90 00 } //01 00 
		$a_01_1 = {b8 48 46 00 00 66 89 07 b8 fa 01 00 00 3b c8 77 05 } //01 00 
		$a_03_2 = {6a 01 6a 28 56 8b c7 e8 90 01 04 85 c0 74 ad 33 ff 81 bd 90 01 02 ff ff 78 56 34 12 74 0e 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}