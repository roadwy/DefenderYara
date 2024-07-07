
rule Ransom_Win32_StopCrypt_MCD_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.MCD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {51 c7 04 24 90 01 04 8b 44 24 08 83 2c 24 04 01 04 24 8b 04 24 31 01 90 00 } //1
		$a_03_1 = {8b c7 c1 e8 90 01 01 8d 34 2f c7 05 90 01 08 c7 05 90 01 08 89 44 24 90 01 01 8b 44 24 20 01 44 24 90 01 01 81 3d 90 01 08 75 90 01 01 8d 4c 24 30 51 68 90 01 04 ff 15 90 01 04 8b 54 24 90 01 01 8b 44 24 90 01 01 33 d6 33 c2 2b d8 81 3d 90 01 08 89 44 24 10 75 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}