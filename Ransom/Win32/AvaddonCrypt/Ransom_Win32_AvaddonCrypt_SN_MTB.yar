
rule Ransom_Win32_AvaddonCrypt_SN_MTB{
	meta:
		description = "Ransom:Win32/AvaddonCrypt.SN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b 4d fc 3b 0d 90 01 04 72 02 eb 90 01 01 8b 15 90 01 04 03 55 fc a1 90 01 04 03 45 fc 8a 08 88 0a 8b 55 fc 83 c2 01 89 55 fc eb 90 01 01 8b e5 5d c3 90 00 } //2
		$a_02_1 = {55 8b ec 53 8b 25 90 01 04 58 8b e8 a1 90 01 04 50 a1 90 01 04 50 8b 1d 90 01 04 ff e3 5b 5d c3 90 00 } //2
	condition:
		((#a_02_0  & 1)*2+(#a_02_1  & 1)*2) >=4
 
}
rule Ransom_Win32_AvaddonCrypt_SN_MTB_2{
	meta:
		description = "Ransom:Win32/AvaddonCrypt.SN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {55 8b ec 83 ec 90 01 01 c7 45 90 01 01 00 00 00 00 a1 90 01 04 03 05 90 01 04 89 45 90 01 01 8b 0d 90 01 04 03 0d 90 01 04 89 4d 90 01 01 eb 00 8b 55 90 01 01 89 55 90 01 01 b8 90 01 04 85 c0 0f 84 90 01 04 eb 00 8b 4d 90 01 01 89 4d 90 01 01 8b 55 90 01 01 3b 55 90 01 01 72 90 00 } //1
		$a_02_1 = {0f b6 0c 0a f7 d9 8b 55 90 01 01 0f b6 04 02 2b c1 8b 4d 90 01 01 03 4d 90 01 01 03 4d 90 01 01 8b 55 90 01 01 88 04 0a c7 45 f0 90 01 04 8b 45 90 01 01 83 c0 01 89 45 90 01 01 e9 90 01 04 8b e5 5d c3 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}