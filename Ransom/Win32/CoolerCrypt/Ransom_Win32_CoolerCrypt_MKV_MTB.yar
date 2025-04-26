
rule Ransom_Win32_CoolerCrypt_MKV_MTB{
	meta:
		description = "Ransom:Win32/CoolerCrypt.MKV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f b6 c9 0f b6 89 f0 70 45 00 33 04 cd 72 2c 47 00 8b 4d ec 8b 55 fc 8b 4c 8a ?? c1 e9 00 0f b6 c9 0f b6 89 f0 70 45 00 33 04 cd 73 2c 47 00 8b 4d f8 8b 55 fc 89 44 8a ?? 8b 45 ec 8b 4d fc 8b 55 f0 89 54 81 0c e9 } //1
		$a_03_1 = {c1 e8 08 89 45 cc 8b 45 cc 8b 4d e0 33 0c c5 ?? ?? ?? ?? 89 4d e0 8b 45 c8 83 c0 20 89 45 c8 8b 45 b4 48 89 45 b4 0f 85 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}