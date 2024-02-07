
rule Trojan_Win64_Ursu_SIB_MTB{
	meta:
		description = "Trojan:Win64/Ursu.SIB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {5c 00 7a 00 6c 00 69 00 62 00 5f 00 63 00 6f 00 6e 00 66 00 69 00 67 00 2e 00 69 00 6e 00 69 00 } //01 00  \zlib_config.ini
		$a_03_1 = {48 89 c3 41 03 ca b8 90 01 04 f7 e1 41 ff c3 c1 ea 90 01 01 89 d0 c1 e0 90 01 01 2b c2 f7 d8 03 c1 44 89 d1 0f b6 13 48 ff c3 33 d0 41 89 c2 41 88 11 49 ff c1 45 3b d8 72 90 00 } //01 00 
		$a_03_2 = {44 0f be 09 45 85 c9 74 90 01 01 45 85 c0 74 90 01 01 41 83 f9 61 45 8d 51 90 01 01 45 0f 43 ca 41 89 c2 41 c1 e2 90 01 01 44 03 d0 43 8d 04 11 4c 8d 49 02 48 ff c1 85 d2 74 90 01 01 4c 89 c9 44 0f be 09 45 85 c9 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}