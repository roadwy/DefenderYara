
rule Ransom_Win32_DharmaCrypt_YAA_MTB{
	meta:
		description = "Ransom:Win32/DharmaCrypt.YAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a c3 32 44 24 17 85 d2 8b 4c 24 20 8b 74 24 20 0f b6 c0 0f b6 c9 0f 45 c8 8b 44 24 28 88 0c 06 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}