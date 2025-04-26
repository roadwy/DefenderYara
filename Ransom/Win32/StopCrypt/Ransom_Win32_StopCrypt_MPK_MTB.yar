
rule Ransom_Win32_StopCrypt_MPK_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.MPK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 06 00 00 "
		
	strings :
		$a_01_0 = {d3 ea 89 55 ec 8b 45 ec 03 45 d4 89 45 ec 8b 4d e4 33 4d f0 89 4d e4 8b 55 e4 33 55 ec 89 55 e4 8b 45 e4 } //1
		$a_01_1 = {d3 e8 89 45 ec 8b 4d ec 03 4d d4 89 4d ec 8b 55 e4 33 55 f0 89 55 e4 8b 45 e4 33 45 ec 89 45 e4 8b 4d e4 } //1
		$a_01_2 = {d3 e8 89 45 ec 8b 4d ec 03 4d d4 89 4d ec 8b 55 e4 33 55 f0 89 55 e4 8b 45 ec 50 8d 4d e4 } //1
		$a_03_3 = {d3 e0 89 45 f8 8b 45 d0 01 45 f8 8b 4d d4 8b c3 c1 e8 [0-01] 89 45 f4 8d 45 f4 } //1
		$a_03_4 = {d3 e0 89 45 f8 8b 45 d0 01 45 f8 8b 4d d4 8b c2 c1 e8 [0-01] 89 45 f4 8d 45 f4 } //1
		$a_03_5 = {d3 e0 89 45 fc 8b 45 d4 01 45 fc 8b 4d d8 8b c2 c1 e8 [0-01] 89 45 f8 8d 45 f8 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1+(#a_03_5  & 1)*1) >=1
 
}