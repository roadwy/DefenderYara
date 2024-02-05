
rule Ransom_Win32_DarkLoader_AA_MTB{
	meta:
		description = "Ransom:Win32/DarkLoader.AA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f b6 04 08 88 04 0f 8b 45 90 01 01 88 14 08 0f b6 04 0f 8b 55 90 01 01 03 c6 0f b6 c0 0f b6 04 08 32 04 1a 88 03 43 83 6d 90 01 01 01 8b 45 90 01 01 90 13 47 81 e7 90 01 04 90 13 8a 14 0f 0f b6 f2 03 c6 25 90 01 04 90 13 89 45 90 01 01 0f b6 04 08 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}