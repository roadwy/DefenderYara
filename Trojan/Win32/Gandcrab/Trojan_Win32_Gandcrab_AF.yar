
rule Trojan_Win32_Gandcrab_AF{
	meta:
		description = "Trojan:Win32/Gandcrab.AF,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 0a 00 "
		
	strings :
		$a_03_0 = {eb 03 c2 0c 00 55 8b ec 81 ec 00 10 00 00 c7 45 90 01 03 00 00 c7 45 90 01 01 00 00 40 00 90 00 } //0a 00 
		$a_03_1 = {e8 04 00 00 00 00 00 00 00 58 89 90 02 05 8b 00 85 c0 74 03 c9 ff e0 90 00 } //00 00 
		$a_00_2 = {7e 15 00 00 1c a5 0a a6 b2 b4 } //b9 ea 
	condition:
		any of ($a_*)
 
}