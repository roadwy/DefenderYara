
rule Trojan_Win32_AveMariaRat_MX_MTB{
	meta:
		description = "Trojan:Win32/AveMariaRat.MX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 05 00 "
		
	strings :
		$a_03_0 = {33 c0 40 d1 e0 33 c9 41 d1 e1 8b 55 90 01 01 8a 04 02 88 44 0d 90 01 01 33 c0 40 6b c0 90 01 01 33 c9 41 6b c9 90 01 01 8b 55 90 01 01 8a 04 02 88 44 0d 90 01 01 33 c0 40 6b c0 90 01 01 8b 4d 90 01 01 c6 04 01 90 01 01 33 c0 40 c1 e0 90 01 01 8b 4d 90 01 01 c6 04 01 90 01 01 33 c0 40 d1 e0 8b 4d 0c c6 04 01 00 33 c0 40 6b c0 90 01 01 8b 4d 90 01 01 c6 04 01 90 01 01 83 65 90 02 05 eb 90 00 } //01 00 
		$a_01_1 = {4e 74 44 65 6c 61 79 45 78 65 63 75 74 69 6f 6e } //01 00 
		$a_01_2 = {49 73 50 72 6f 63 65 73 73 6f 72 46 65 61 74 75 72 65 50 72 65 73 65 6e 74 } //00 00 
	condition:
		any of ($a_*)
 
}