
rule Ransom_Win32_Stopcrypt_YAI_MTB{
	meta:
		description = "Ransom:Win32/Stopcrypt.YAI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b c1 c1 e8 05 03 44 24 90 01 01 03 cf 33 c2 33 c1 2b f0 8b d6 c1 e2 04 89 44 24 90 01 01 c7 05 90 01 08 89 54 24 90 00 } //01 00 
		$a_03_1 = {33 d7 31 54 24 0c 8b 44 24 0c 29 44 24 10 8d 44 24 20 e8 90 01 04 ff 4c 24 18 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}