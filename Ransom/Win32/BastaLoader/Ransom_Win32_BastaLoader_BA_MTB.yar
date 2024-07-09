
rule Ransom_Win32_BastaLoader_BA_MTB{
	meta:
		description = "Ransom:Win32/BastaLoader.BA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {13 d6 66 8b 10 66 89 55 ?? 8b 45 ?? 83 c0 ?? 89 45 ?? 0f b7 4d ?? 8b 55 ?? c1 ea ?? 8b 45 ?? c1 e0 ?? 0b d0 03 ca 33 4d ?? 89 4d ?? eb } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}