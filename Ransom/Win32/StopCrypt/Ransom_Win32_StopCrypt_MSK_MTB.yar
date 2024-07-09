
rule Ransom_Win32_StopCrypt_MSK_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.MSK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {c1 e0 04 89 01 c3 } //1
		$a_03_1 = {33 74 24 0c 8b 44 24 08 89 30 5e c2 08 00 33 44 24 04 c2 04 00 81 00 [0-04] c3 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Ransom_Win32_StopCrypt_MSK_MTB_2{
	meta:
		description = "Ransom:Win32/StopCrypt.MSK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 55 f4 c1 e2 [0-01] 89 55 e4 8b 45 f8 01 45 e4 8b 45 f4 03 45 e8 89 45 f0 c7 05 [0-08] c7 05 [0-04] ff ff ff ff 8b 45 f4 8b 8d 40 ff ff ff d3 e8 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}