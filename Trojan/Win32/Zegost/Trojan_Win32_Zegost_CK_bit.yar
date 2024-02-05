
rule Trojan_Win32_Zegost_CK_bit{
	meta:
		description = "Trojan:Win32/Zegost.CK!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {4b c6 44 24 90 01 01 52 c6 44 24 90 01 01 4e c6 44 24 90 01 01 4c c6 44 24 90 01 01 33 c6 44 24 90 01 01 32 c6 44 24 90 01 01 2e 90 00 } //01 00 
		$a_03_1 = {5c c6 44 24 90 01 01 75 c6 44 24 90 01 01 70 c6 44 24 90 01 01 64 c6 44 24 90 01 01 61 c6 44 24 90 01 01 74 c6 44 24 90 01 01 61 c6 44 24 90 01 01 00 90 00 } //01 00 
		$a_03_2 = {8a 14 01 80 c2 90 01 01 80 f2 90 01 01 88 14 01 83 c1 01 3b ce 7c ed 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}