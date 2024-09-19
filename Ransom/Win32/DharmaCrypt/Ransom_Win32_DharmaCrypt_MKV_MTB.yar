
rule Ransom_Win32_DharmaCrypt_MKV_MTB{
	meta:
		description = "Ransom:Win32/DharmaCrypt.MKV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {33 42 34 8b 4d f4 89 41 38 8b 55 f4 8b 45 f4 8b 4a 1c 33 48 38 8b 55 f4 89 4a 3c 8b 45 f4 83 c0 20 89 45 f4 e9 72 fe ff ff } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}