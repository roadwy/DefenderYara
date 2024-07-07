
rule Ransom_Win32_StopCrypt_MLA_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.MLA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b d7 d3 ea 8d 04 3b 89 45 f0 c7 05 90 01 04 ee 3d ea f4 03 55 e4 8b 45 f0 31 45 fc 33 55 fc 81 3d 90 01 04 13 02 00 00 89 55 f0 75 90 00 } //1
		$a_03_1 = {c1 e0 04 89 45 fc 8b 45 dc 01 45 fc 8b 55 f4 8b 4d f8 8b c2 d3 e8 8d 3c 13 81 c3 90 01 04 03 45 e0 33 c7 31 45 fc 8b 45 fc 29 45 ec ff 4d e8 0f 85 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}