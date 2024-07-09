
rule Ransom_Win32_StopCrypt_MZC_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.MZC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 4d f8 03 c8 33 f9 8b 4d [0-01] d3 e8 89 7d [0-01] c7 05 [0-08] 03 45 [0-01] 33 c7 8b f8 83 fa [0-01] 75 } //1
		$a_03_1 = {8b c3 c1 e0 [0-01] 03 45 e8 89 45 fc 8b 45 f8 03 c3 89 45 d8 8b 45 d8 31 45 fc 8b c3 c1 e8 [0-01] 03 45 dc 89 35 [0-04] 31 45 fc 8b 45 fc 29 45 f4 8b 45 e4 29 45 f8 ff 4d ec 0f 85 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}