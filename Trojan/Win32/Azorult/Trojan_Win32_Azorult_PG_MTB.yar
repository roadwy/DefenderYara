
rule Trojan_Win32_Azorult_PG_MTB{
	meta:
		description = "Trojan:Win32/Azorult.PG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b 45 6c 03 45 60 89 45 54 8b 4d 6c c1 e9 05 89 4d 70 8b 55 70 03 55 4c 89 55 70 8b 45 74 33 45 54 89 45 74 c7 05 90 01 04 f4 6e e0 f7 8b 4d 74 33 4d 70 89 4d 70 90 00 } //01 00 
		$a_02_1 = {ba 04 00 00 00 6b c2 00 8b 4d 64 8b 14 01 89 55 48 b8 04 00 00 00 c1 e0 00 8b 4d 64 8b 14 01 89 55 44 b8 04 00 00 00 d1 e0 8b 4d 64 8b 14 01 89 55 50 81 3d 90 01 04 85 0f 00 00 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}