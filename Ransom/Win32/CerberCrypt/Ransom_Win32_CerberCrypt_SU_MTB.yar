
rule Ransom_Win32_CerberCrypt_SU_MTB{
	meta:
		description = "Ransom:Win32/CerberCrypt.SU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {c1 e9 05 03 4d ?? c1 e0 04 03 45 ?? 33 c8 8d 04 3b 33 c8 2b f1 8b ce 8b c6 c1 e9 05 03 4d ?? c1 e0 04 03 45 ?? 33 c8 8d 04 33 33 c8 8d 9b } //1
		$a_03_1 = {2b f9 ff 4d ?? 75 ?? 8b 45 ?? 8b 5d ?? 89 38 8b 45 ?? 89 30 8b 45 ?? 40 89 45 ?? 3b 45 ?? 0f 82 ?? ff ff ff 5f 5e 5b 8b e5 5d c3 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}