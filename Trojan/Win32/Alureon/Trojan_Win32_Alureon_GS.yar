
rule Trojan_Win32_Alureon_GS{
	meta:
		description = "Trojan:Win32/Alureon.GS,SIGNATURE_TYPE_ARHSTR_EXT,03 00 03 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {5b 53 43 52 49 50 54 5f 53 49 47 4e 41 54 55 52 45 5f 43 48 45 43 4b 5d } //01 00 
		$a_01_1 = {5b 6b 69 74 5f 68 61 73 68 5f 65 6e 64 5d } //01 00 
		$a_01_2 = {5b 63 6d 64 5f 64 6c 6c 5f 68 61 73 68 5f 65 6e 64 5d } //02 00 
		$a_03_3 = {8a d0 80 c2 51 30 90 90 90 01 04 83 c0 01 3d 00 01 00 00 72 eb 90 00 } //02 00 
		$a_03_4 = {8a c8 80 c1 51 30 88 90 01 04 83 c0 01 83 f8 20 72 ed 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}