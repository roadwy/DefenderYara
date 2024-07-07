
rule Ransom_Win32_StopCrypt_OTG_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.OTG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b c6 c1 e0 04 89 45 fc 8b 45 d8 01 45 fc 8b 4d f4 8d 04 33 89 45 e8 8b c6 d3 e8 03 45 d4 89 45 f8 8b 45 e8 31 45 fc 81 3d 90 01 04 03 0b 00 00 75 90 00 } //1
		$a_03_1 = {33 45 f8 81 c3 90 01 04 2b f8 ff 4d e4 89 45 fc 89 7d ec 0f 85 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}