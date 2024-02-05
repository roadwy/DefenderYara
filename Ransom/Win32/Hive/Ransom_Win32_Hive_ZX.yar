
rule Ransom_Win32_Hive_ZX{
	meta:
		description = "Ransom:Win32/Hive.ZX,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 0a 00 "
		
	strings :
		$a_03_0 = {83 ec 50 a1 90 01 04 89 ce c7 45 f0 03 01 00 00 c7 45 f4 00 00 00 00 85 c0 74 40 89 d7 8d 4d f0 6a 00 6a 00 ff 75 0c ff 75 08 51 6a 00 6a 00 6a 00 52 ff d0 3d 03 01 00 00 75 12 6a ff 57 e8 90 01 04 8b 45 f0 3d 03 01 00 00 90 00 } //0a 00 
		$a_03_1 = {31 f6 b9 46 02 00 00 46 89 f2 e8 90 01 04 b9 02 00 00 00 89 54 24 34 51 90 01 01 46 02 00 00 90 01 01 89 44 24 38 50 31 c0 50 e8 90 01 04 b9 46 02 00 00 89 f2 e8 90 01 04 89 d6 b9 02 00 00 00 51 90 02 05 89 44 24 34 50 31 c0 50 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}