
rule Trojan_Win32_Alureon_DY{
	meta:
		description = "Trojan:Win32/Alureon.DY,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 02 00 "
		
	strings :
		$a_01_0 = {c6 45 f8 74 c6 45 f9 64 c6 45 fa 6c 39 } //02 00 
		$a_03_1 = {6a 21 6a 7c 50 89 45 90 01 01 e8 90 01 04 6a 20 6a 3b 90 00 } //01 00 
		$a_03_2 = {0f b7 43 06 83 c2 28 ff 45 90 01 01 89 55 90 01 01 39 45 90 00 } //01 00 
		$a_01_3 = {3c 0d 75 04 c6 06 00 46 80 3e 0a } //01 00 
		$a_03_4 = {50 6a 5a 68 00 08 00 00 ff 15 90 01 04 85 c0 75 0e be 90 01 04 8d bd 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}