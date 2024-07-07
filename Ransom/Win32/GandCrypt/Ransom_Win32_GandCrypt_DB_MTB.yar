
rule Ransom_Win32_GandCrypt_DB_MTB{
	meta:
		description = "Ransom:Win32/GandCrypt.DB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 fc 83 c0 01 89 45 fc 8b 4d fc 3b 4d f4 7d 90 01 01 8b 55 f8 03 55 fc 0f be 1a e8 90 01 04 33 d8 8b 45 f8 03 45 fc 88 18 eb 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}