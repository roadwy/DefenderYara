
rule Trojan_Win32_Stealer_CG_MTB{
	meta:
		description = "Trojan:Win32/Stealer.CG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {89 55 74 b8 3b 2d 0b 00 01 45 74 8b 45 74 8a 04 08 88 04 31 41 3b 0d 90 02 04 0f 82 90 00 } //01 00 
		$a_01_1 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //01 00 
		$a_01_2 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //01 00 
		$a_01_3 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //00 00 
	condition:
		any of ($a_*)
 
}