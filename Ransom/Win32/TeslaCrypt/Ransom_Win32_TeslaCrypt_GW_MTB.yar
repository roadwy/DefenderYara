
rule Ransom_Win32_TeslaCrypt_GW_MTB{
	meta:
		description = "Ransom:Win32/TeslaCrypt.GW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {81 f1 69 3d 00 00 8b b4 24 d0 00 00 00 81 f6 1d 7e 00 00 8b 7c 24 40 29 f8 89 84 24 } //2
		$a_01_1 = {80 c1 08 8b b4 24 d0 00 00 00 81 f6 69 3d 00 00 01 f2 89 54 24 5c 38 c8 0f } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}