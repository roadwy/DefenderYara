
rule Ransom_Win32_GandCrab_AD_MTB{
	meta:
		description = "Ransom:Win32/GandCrab.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 04 00 "
		
	strings :
		$a_02_0 = {c1 e8 1e 35 71 87 fb 3c 81 90 01 02 20 b9 00 6b 81 90 01 02 20 b9 00 6b 81 90 01 02 5a ce 13 12 81 90 01 02 72 23 32 5d 81 90 01 02 cc f1 45 6f c1 90 01 01 03 90 00 } //01 00 
		$a_02_1 = {c1 e8 1e 35 71 87 fb 3c 90 08 00 04 c6 05 90 01 04 6b 90 00 } //00 00 
		$a_00_2 = {5d } //04 00  ]
	condition:
		any of ($a_*)
 
}
rule Ransom_Win32_GandCrab_AD_MTB_2{
	meta:
		description = "Ransom:Win32/GandCrab.AD!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {64 61 6c 61 74 65 62 69 6a 61 79 75 63 6f 67 75 7a 65 6e 75 6b 6f 77 6f 77 61 77 6f 73 61 73 69 79 6f 7a 69 77 69 77 61 63 75 6d 6f } //01 00  dalatebijayucoguzenukowowawosasiyoziwiwacumo
		$a_01_1 = {53 61 73 65 76 75 6a 69 } //01 00  Sasevuji
		$a_01_2 = {66 00 72 00 61 00 6d 00 69 00 66 00 6f 00 6d 00 6f 00 78 00 61 00 76 00 6f 00 6b 00 61 00 72 00 75 00 6e 00 65 00 6e 00 6f 00 79 00 69 00 } //00 00  framifomoxavokarunenoyi
	condition:
		any of ($a_*)
 
}