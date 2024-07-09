
rule Ransom_Win32_StopCrypt_MZE_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.MZE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 4d f4 03 cf 33 d1 8b 4d [0-01] 8b f7 d3 ee c7 05 [0-08] 89 55 [0-01] 03 75 [0-01] 33 f2 83 f8 [0-01] 75 } //1
		$a_03_1 = {8b 4d f0 8b c1 c1 e0 [0-01] 03 45 e0 89 45 fc 8b 45 f4 03 c1 89 45 dc 8b 45 dc 31 45 fc ff 75 fc c1 e9 [0-01] 03 4d d8 8d 45 fc } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}