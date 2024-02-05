
rule Trojan_Win32_AveMariaRat_MZ_MTB{
	meta:
		description = "Trojan:Win32/AveMariaRat.MZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {33 c0 40 6b c0 90 01 01 33 c9 41 6b c9 90 01 01 8b 55 90 01 01 8a 04 02 88 44 0d 90 01 01 33 c0 40 6b c0 90 01 01 8b 4d 90 01 01 c6 04 01 90 01 01 33 c0 40 c1 e0 00 8b 4d 90 01 01 c6 04 01 90 01 01 33 c0 40 d1 e0 8b 4d 94 c6 04 01 90 01 01 33 c0 40 6b c0 90 01 01 8b 4d 90 01 01 c6 04 01 90 01 01 83 65 90 01 02 eb 90 00 } //01 00 
		$a_01_1 = {57 6f 77 36 34 47 65 74 54 68 72 65 61 64 43 6f 6e 74 65 78 74 } //01 00 
		$a_01_2 = {49 73 50 72 6f 63 65 73 73 6f 72 46 65 61 74 75 72 65 50 72 65 73 65 6e 74 } //00 00 
	condition:
		any of ($a_*)
 
}