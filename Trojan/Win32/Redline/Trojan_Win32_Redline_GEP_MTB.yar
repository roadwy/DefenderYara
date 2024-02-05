
rule Trojan_Win32_Redline_GEP_MTB{
	meta:
		description = "Trojan:Win32/Redline.GEP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 0a 00 "
		
	strings :
		$a_03_0 = {0f be 04 10 6b c0 90 01 01 99 b9 90 01 04 f7 f9 6b c0 90 01 01 6b c0 90 01 01 8b 55 90 01 01 03 55 90 01 01 0f b6 0a 33 c8 8b 55 90 01 01 03 55 90 01 01 88 0a 90 00 } //01 00 
		$a_03_1 = {5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 2e 00 4e 00 45 00 54 00 5c 00 46 00 72 00 61 00 6d 00 65 00 77 00 6f 00 72 00 6b 00 5c 00 90 02 20 5c 00 41 00 70 00 70 00 4c 00 61 00 75 00 6e 00 63 00 68 00 2e 00 65 00 78 00 65 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}