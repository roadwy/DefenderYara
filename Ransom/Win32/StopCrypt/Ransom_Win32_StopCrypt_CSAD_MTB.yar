
rule Ransom_Win32_StopCrypt_CSAD_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.CSAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {03 44 24 28 57 8d 4c 24 14 89 44 24 18 c7 05 90 90 bc 6a 00 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 44 24 14 33 44 24 10 c7 05 90 90 bc 6a 00 00 00 00 00 2b f0 8b ce c1 e1 ?? 89 44 24 14 89 4c 24 10 8b 44 24 2c 01 44 24 10 8b d6 c1 ea ?? 8d 3c 33 c7 05 98 bc 6a 00 ?? ?? ?? ?? c7 05 9c bc 6a 00 ?? ?? ?? ?? 89 54 24 14 8b 44 24 24 01 44 24 14 81 3d 3c 13 6b 00 ?? ?? ?? ?? 75 } //1
		$a_03_1 = {8b 4c 24 14 8b 44 24 10 33 cf 33 c1 2b e8 81 3d 3c 13 6b 00 ?? ?? ?? ?? 89 44 24 10 75 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}