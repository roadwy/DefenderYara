
rule Ransom_Win32_TeslaCrypt_CCHW_MTB{
	meta:
		description = "Ransom:Win32/TeslaCrypt.CCHW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f be 00 8b 4c 24 18 0f be 09 29 c8 83 f8 00 0f 95 c2 80 f2 ff 80 e2 01 88 54 24 27 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}