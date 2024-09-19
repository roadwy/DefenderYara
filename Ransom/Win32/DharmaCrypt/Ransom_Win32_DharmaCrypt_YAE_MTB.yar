
rule Ransom_Win32_DharmaCrypt_YAE_MTB{
	meta:
		description = "Ransom:Win32/DharmaCrypt.YAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8d 14 38 8d 3c 82 89 7d d4 8a c3 32 45 0f 88 45 0f 0f b7 4d d8 0f b7 45 a4 0f af c1 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}