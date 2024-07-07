
rule Ransom_Win32_StopCrypt_MJK_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.MJK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b 4d f0 33 c8 89 45 f8 2b f9 25 90 02 04 8b c7 8d 4d f8 e8 90 02 04 8b 4d d8 8b c7 c1 e8 90 02 01 89 45 f0 8d 45 f0 90 00 } //1
		$a_03_1 = {8b 4d f0 33 c8 89 45 f8 2b f9 25 90 02 04 8b c7 8d 4d f8 e8 90 02 04 8b 4d e0 8b c7 c1 e8 90 02 01 89 45 f0 8d 45 f0 90 00 } //1
		$a_03_2 = {8b 4d f8 33 c8 89 45 fc 2b f9 25 90 02 04 8b c7 8d 4d fc e8 90 02 04 8b 4d e0 8b c7 c1 e8 90 02 01 89 45 f8 8d 45 f8 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=1
 
}