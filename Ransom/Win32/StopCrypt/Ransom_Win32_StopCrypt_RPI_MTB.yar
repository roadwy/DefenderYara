
rule Ransom_Win32_StopCrypt_RPI_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.RPI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {8d 0c 03 8b 45 f4 03 c6 33 c8 33 4d f8 89 4d f8 8b 45 f8 } //1
		$a_01_1 = {2b f9 8b c7 c1 e0 04 03 45 ec 8b d7 89 45 f8 8b 45 f4 03 c7 c1 ea 05 03 55 e0 50 8d 4d f8 } //1
		$a_01_2 = {8b 45 08 89 78 04 5f 89 30 5e 5b c9 c2 04 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}