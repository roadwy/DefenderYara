
rule Ransom_Win32_DharmaCrypt_YAF_MTB{
	meta:
		description = "Ransom:Win32/DharmaCrypt.YAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 15 30 0b 44 00 0f b6 45 e3 33 45 d8 88 45 eb 8b 4d c8 3b 4d 98 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}