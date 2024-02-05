
rule Trojan_Win32_Warece_D{
	meta:
		description = "Trojan:Win32/Warece.D,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {84 d2 74 08 41 88 10 40 8a 11 eb f4 } //01 00 
		$a_03_1 = {c6 00 77 a1 90 01 03 10 c6 40 08 6c 90 00 } //01 00 
		$a_03_2 = {74 1a 8b ce 8a 94 90 01 03 ff ff 3a c2 75 0d 84 d2 74 09 8a 41 01 90 01 01 41 84 c0 75 e8 90 00 } //01 00 
		$a_01_3 = {77 6f 77 66 78 2e 64 6c 6c 00 } //00 00 
	condition:
		any of ($a_*)
 
}