
rule Ransom_Win32_BastaLoader_BA_MTB{
	meta:
		description = "Ransom:Win32/BastaLoader.BA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {13 d6 66 8b 10 66 89 55 90 01 01 8b 45 90 01 01 83 c0 90 01 01 89 45 90 01 01 0f b7 4d 90 01 01 8b 55 90 01 01 c1 ea 90 01 01 8b 45 90 01 01 c1 e0 90 01 01 0b d0 03 ca 33 4d 90 01 01 89 4d 90 01 01 eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}