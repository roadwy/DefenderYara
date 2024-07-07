
rule Ransom_Win32_CerberCrypt_SU_MTB{
	meta:
		description = "Ransom:Win32/CerberCrypt.SU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {c1 e9 05 03 4d 90 01 01 c1 e0 04 03 45 90 01 01 33 c8 8d 04 3b 33 c8 2b f1 8b ce 8b c6 c1 e9 05 03 4d 90 01 01 c1 e0 04 03 45 90 01 01 33 c8 8d 04 33 33 c8 8d 9b 90 00 } //1
		$a_03_1 = {2b f9 ff 4d 90 01 01 75 90 01 01 8b 45 90 01 01 8b 5d 90 01 01 89 38 8b 45 90 01 01 89 30 8b 45 90 01 01 40 89 45 90 01 01 3b 45 90 01 01 0f 82 90 01 01 ff ff ff 5f 5e 5b 8b e5 5d c3 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}