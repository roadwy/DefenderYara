
rule Ransom_Win32_HydraCrypt_YAA_MTB{
	meta:
		description = "Ransom:Win32/HydraCrypt.YAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 4d f0 83 c1 01 33 4d f8 03 c1 88 45 ff 8b 55 f0 8a 45 ff 88 82 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}