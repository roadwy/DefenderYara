
rule Trojan_Win32_Redline_ASBF_MTB{
	meta:
		description = "Trojan:Win32/Redline.ASBF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {33 f5 31 74 24 10 8b 44 24 10 29 44 24 14 c7 44 24 18 00 00 00 00 8b 44 24 38 01 44 24 18 2b 5c 24 18 ff 4c 24 20 0f } //01 00 
		$a_01_1 = {68 69 62 75 62 75 77 61 79 61 6d 69 76 75 6b 69 64 61 77 65 79 61 76 61 6d } //00 00  hibubuwayamivukidaweyavam
	condition:
		any of ($a_*)
 
}