
rule Ransom_Win32_NokonokoPacker_ZC_MTB{
	meta:
		description = "Ransom:Win32/NokonokoPacker.ZC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8d 1c 02 8b 55 90 01 01 8b 45 90 01 01 01 d0 0f b6 30 8b 4d 90 01 01 ba 90 01 04 89 c8 f7 ea c1 fa 90 01 01 89 c8 c1 f8 90 01 01 29 c2 89 d0 c1 e0 02 01 d0 c1 e0 90 01 01 01 d0 29 c1 89 ca 8b 45 90 01 01 01 d0 0f b6 00 31 f0 88 03 83 45 90 01 02 8b 55 90 01 01 8b 45 90 01 01 39 c2 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}