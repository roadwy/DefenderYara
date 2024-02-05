
rule Ransom_Win32_Locky_DAS_MTB{
	meta:
		description = "Ransom:Win32/Locky.DAS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {74 22 49 74 07 88 44 34 20 46 eb 4e 6a 0b 53 6a 07 59 e8 c5 fe ff ff 8b f8 59 59 85 ff 74 3b 57 6a 00 eb 27 6a 03 59 51 53 eb e7 8a 44 34 1f 6a 03 53 6a 02 59 88 44 24 18 } //02 00 
		$a_01_1 = {83 e4 f8 8b 45 14 66 0f 6e 45 18 66 0f 6e 55 10 83 a1 24 01 00 00 00 33 d2 42 66 0f 6e da 8b 55 0c 66 0f 6e c8 66 0f 62 d0 51 66 0f 62 d9 66 0f 62 da 66 0f 7f 59 10 8b 4d 08 e8 d8 fd ff ff 8b e5 5d c2 14 } //00 00 
	condition:
		any of ($a_*)
 
}