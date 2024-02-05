
rule Trojan_Win32_Redline_BV_MTB{
	meta:
		description = "Trojan:Win32/Redline.BV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {99 f7 fe 89 c2 8b 45 f0 6b d2 90 01 01 31 d1 01 c8 88 c2 8b 45 0c 8b 4d f8 88 14 08 0f be 75 f7 8b 45 0c 8b 4d f8 0f be 14 08 29 f2 88 14 08 8b 45 f8 83 c0 01 89 45 f8 e9 90 00 } //02 00 
		$a_03_1 = {5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 2e 00 4e 00 45 00 54 00 5c 00 46 00 72 00 61 00 6d 00 65 00 77 00 6f 00 72 00 6b 00 5c 00 90 02 20 5c 00 41 00 70 00 70 00 4c 00 61 00 75 00 6e 00 63 00 68 00 2e 00 65 00 78 00 65 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}