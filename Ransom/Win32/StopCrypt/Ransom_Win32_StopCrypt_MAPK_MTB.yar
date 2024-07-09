
rule Ransom_Win32_StopCrypt_MAPK_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.MAPK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {55 8b ec 51 c7 45 fc [0-04] 8b 45 10 8b 4d fc d3 e8 8b 4d 08 89 01 8b 55 08 8b 02 03 45 0c 8b 4d 08 89 01 8b e5 5d c2 } //1
		$a_03_1 = {8b 45 e4 33 45 f0 89 45 e4 8b 4d ec 33 4d e4 89 4d ec c7 05 [0-08] 8b 45 ec 01 05 [0-04] 8b 45 ec 29 45 f4 8b 55 f4 c1 e2 04 89 55 e4 8b 45 f8 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}