
rule Ransom_Win32_HydraCrypt_YAB_MTB{
	meta:
		description = "Ransom:Win32/HydraCrypt.YAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {f7 e1 c1 ea 03 8d 14 92 03 d2 8b c1 2b c2 8a 54 04 10 30 14 39 41 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}