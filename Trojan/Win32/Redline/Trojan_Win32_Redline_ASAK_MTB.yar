
rule Trojan_Win32_Redline_ASAK_MTB{
	meta:
		description = "Trojan:Win32/Redline.ASAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {c7 04 24 33 b3 5a 42 e8 } //01 00 
		$a_01_1 = {64 75 67 69 55 73 75 41 65 } //01 00 
		$a_01_2 = {c1 d9 06 66 81 f3 3b 03 66 4f 66 bf aa 01 c1 e2 20 83 e6 73 } //01 00 
		$a_03_3 = {5c 4d 69 63 72 6f 73 6f 66 74 2e 4e 45 54 5c 46 72 61 6d 65 77 6f 72 6b 5c 90 02 20 5c 41 70 70 4c 61 75 6e 63 68 2e 65 78 65 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}