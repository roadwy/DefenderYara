
rule Ransom_Win32_BastaLoader_MA_MTB{
	meta:
		description = "Ransom:Win32/BastaLoader.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {83 c4 08 85 c0 75 90 01 01 8b 45 fc 0f b6 48 5a 85 c9 75 90 01 01 c7 45 f8 01 00 00 00 eb 90 01 01 c7 45 f8 00 00 00 00 8b 55 fc 8a 45 f8 88 42 5a 8b e5 5d c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}