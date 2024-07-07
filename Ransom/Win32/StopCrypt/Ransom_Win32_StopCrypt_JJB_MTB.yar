
rule Ransom_Win32_StopCrypt_JJB_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.JJB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b c1 c1 e0 04 03 44 24 28 03 f9 c1 e9 05 83 3d 90 01 04 1b 89 44 24 10 8b d9 75 0e 6a 00 6a 00 ff 15 90 01 04 8b 44 24 10 03 dd 33 df 33 d8 2b f3 8b c6 90 00 } //1
		$a_03_1 = {8b ce c1 e9 05 03 4c 24 24 c7 05 90 01 04 19 36 6b ff 33 cf 31 4c 24 10 c7 05 90 01 04 ff ff ff ff 8b 44 24 10 29 44 24 18 8b 44 24 2c 29 44 24 14 ff 4c 24 1c 0f 85 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}