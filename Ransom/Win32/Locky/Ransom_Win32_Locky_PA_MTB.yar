
rule Ransom_Win32_Locky_PA_MTB{
	meta:
		description = "Ransom:Win32/Locky.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {f7 d0 33 c9 83 e9 01 23 4d 90 01 01 03 c1 32 d2 fe ca 32 55 90 01 01 f6 d2 8b f8 89 15 90 01 03 00 a1 90 01 03 00 32 45 90 01 01 88 07 32 45 90 01 01 80 37 eb 90 00 } //01 00 
		$a_03_1 = {8a 00 02 45 90 01 01 89 7d 90 01 01 0f b6 c0 89 45 90 01 01 0f af d7 03 ca 89 0d 90 01 03 00 8b 45 90 01 01 0b 45 90 01 01 33 45 90 01 01 f7 d0 33 c9 83 e9 01 23 4d 90 01 01 03 c1 32 d2 fe ca 32 55 90 01 01 f6 d2 8b f8 89 15 90 01 03 00 a1 90 01 03 00 32 45 90 01 01 88 07 32 45 90 01 01 80 37 eb 90 00 } //00 00 
		$a_00_2 = {5d } //04 00  ]
	condition:
		any of ($a_*)
 
}