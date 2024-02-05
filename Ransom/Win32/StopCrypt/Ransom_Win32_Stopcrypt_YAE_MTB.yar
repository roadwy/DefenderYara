
rule Ransom_Win32_Stopcrypt_YAE_MTB{
	meta:
		description = "Ransom:Win32/Stopcrypt.YAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {8b 45 dc 01 45 fc 8b 45 f4 8b 4d f8 8d 14 01 8b 4d f0 d3 e8 03 45 d8 33 c2 31 45 fc 2b 7d fc 8b 45 d4 29 45 f8 ff 4d ec 0f 85 } //00 00 
	condition:
		any of ($a_*)
 
}