
rule Trojan_Win32_Alureon_CV{
	meta:
		description = "Trojan:Win32/Alureon.CV,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 03 00 "
		
	strings :
		$a_03_0 = {76 0f 8a d1 80 c2 90 01 01 30 14 01 41 3b 4c 24 04 72 f1 90 00 } //03 00 
		$a_03_1 = {68 44 49 42 47 90 01 01 32 4c 44 54 90 00 } //01 00 
		$a_01_2 = {68 44 49 41 47 } //01 00 
		$a_01_3 = {68 54 4e 43 47 } //01 00 
		$a_01_4 = {2f 61 64 63 2e 70 68 70 } //00 00 
	condition:
		any of ($a_*)
 
}