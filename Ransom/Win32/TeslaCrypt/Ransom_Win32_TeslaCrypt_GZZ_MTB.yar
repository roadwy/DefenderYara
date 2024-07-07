
rule Ransom_Win32_TeslaCrypt_GZZ_MTB{
	meta:
		description = "Ransom:Win32/TeslaCrypt.GZZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 4c 24 7c 81 f1 5c 4b 00 00 03 4c 24 50 89 4c 24 50 2b 44 24 7c 39 44 24 50 90 01 02 8a 44 24 34 0c 7e 88 84 24 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}
rule Ransom_Win32_TeslaCrypt_GZZ_MTB_2{
	meta:
		description = "Ransom:Win32/TeslaCrypt.GZZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {01 c7 89 f8 88 c1 8b 44 24 90 01 01 8b 7c 24 90 01 01 88 4c 24 90 01 01 29 c2 19 fe 89 54 24 90 01 01 89 74 24 90 01 05 8b 44 24 64 8a 4c 24 2f 88 08 e9 90 01 04 8b 44 24 90 01 01 8b 4c 24 68 81 f1 0e 1c 00 00 39 c8 0f 87 90 00 } //10
		$a_01_1 = {43 6c 77 6f 6f 39 } //1 Clwoo9
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}