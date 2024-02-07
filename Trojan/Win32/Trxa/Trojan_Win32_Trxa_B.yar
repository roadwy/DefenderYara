
rule Trojan_Win32_Trxa_B{
	meta:
		description = "Trojan:Win32/Trxa.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {80 3f 23 8b c7 74 0c 8a 08 40 84 c9 74 20 80 38 23 75 f4 } //01 00 
		$a_01_1 = {00 71 3d 66 6f 72 6d 67 72 61 62 62 65 72 00 } //01 00 
		$a_00_2 = {3c 52 65 70 4c 6f 6f 6b 75 70 20 76 3d 22 33 22 3e } //01 00  <RepLookup v="3">
		$a_00_3 = {00 46 6f 72 6d 47 72 61 62 62 65 72 44 6c 6c 2e 64 6c 6c 00 } //00 00 
	condition:
		any of ($a_*)
 
}