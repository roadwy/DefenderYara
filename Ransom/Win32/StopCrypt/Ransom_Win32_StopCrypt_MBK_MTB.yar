
rule Ransom_Win32_StopCrypt_MBK_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.MBK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8d 1c 01 c1 e8 05 89 45 90 02 01 c7 05 90 02 08 8b 85 90 90 fd ff ff 01 45 90 1b 00 81 3d 90 02 06 00 00 75 90 00 } //1
		$a_03_1 = {8b 45 74 31 45 90 02 01 89 3d 90 02 04 8b 45 90 02 01 29 45 90 02 01 81 3d 90 02 06 00 00 75 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Ransom_Win32_StopCrypt_MBK_MTB_2{
	meta:
		description = "Ransom:Win32/StopCrypt.MBK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_03_0 = {2b 5d fc 89 75 ec 25 90 02 04 81 6d ec 90 02 04 81 45 ec 90 02 04 8b 4d dc 8b c3 c1 e8 90 02 01 89 45 fc 8d 45 fc 90 00 } //1
		$a_03_1 = {2b 5d f8 89 7d e8 25 90 02 04 81 6d e8 90 02 04 81 45 e8 90 02 04 8b 4d dc 8b c3 c1 e8 90 02 01 89 45 f8 8d 45 f8 90 00 } //1
		$a_03_2 = {33 45 f4 89 7d ec 2b d8 25 90 02 04 81 6d ec 90 02 04 81 45 ec 90 02 04 8b 4d d4 8b c3 c1 e8 90 02 01 89 45 f4 8d 45 f4 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=1
 
}