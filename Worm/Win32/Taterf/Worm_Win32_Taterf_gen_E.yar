
rule Worm_Win32_Taterf_gen_E{
	meta:
		description = "Worm:Win32/Taterf.gen!E,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 85 30 f0 ff ff 8d bc 05 f8 ef ff ff 0f b7 84 05 08 f0 ff ff 8d 77 14 03 c6 89 45 f4 8b 45 10 3b c3 74 05 8b 4e 1c 89 08 ff 76 38 e8 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Worm_Win32_Taterf_gen_E_2{
	meta:
		description = "Worm:Win32/Taterf.gen!E,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_01_0 = {ff d7 25 ff ff 00 00 3d 16 1c 00 00 76 08 3d 20 1c 00 00 73 01 cc } //1
		$a_03_1 = {ff d6 bf ff ff 00 00 23 c7 3d 16 1c 00 00 76 (?? 3d 20 1c 00 00 73 ?? cc 0f 3d 20 1c|00 00 73 08 6a 00 ff 15 )} //1
		$a_03_2 = {58 83 38 00 75 1f ff 00 ff 74 24 10 ff 74 24 10 ff 74 24 10 ff 74 24 10 90 09 09 00 e8 04 00 00 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=1
 
}