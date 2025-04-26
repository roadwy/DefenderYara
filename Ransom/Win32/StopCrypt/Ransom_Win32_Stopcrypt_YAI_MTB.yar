
rule Ransom_Win32_Stopcrypt_YAI_MTB{
	meta:
		description = "Ransom:Win32/Stopcrypt.YAI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 f8 8b 55 f4 33 45 ec 81 c3 ?? ?? ?? ?? 8b 4d dc 2b f0 89 45 f8 89 75 fc 4f } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Ransom_Win32_Stopcrypt_YAI_MTB_2{
	meta:
		description = "Ransom:Win32/Stopcrypt.YAI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b c1 c1 e8 05 03 44 24 ?? 03 cf 33 c2 33 c1 2b f0 8b d6 c1 e2 04 89 44 24 ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 54 24 } //1
		$a_03_1 = {33 d7 31 54 24 0c 8b 44 24 0c 29 44 24 10 8d 44 24 20 e8 ?? ?? ?? ?? ff 4c 24 18 0f 85 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}