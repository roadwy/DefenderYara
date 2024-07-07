
rule Ransom_Win32_StopCrypt_MJW_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.MJW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b c6 c1 e8 05 03 44 24 20 03 cd 33 c1 8b 4c 24 18 03 ce 33 c1 2b f8 8b d7 c1 e2 04 81 3d 90 01 04 8c 07 00 00 89 44 24 14 c7 05 90 01 04 00 00 00 00 89 54 24 10 75 90 00 } //1
		$a_03_1 = {8b 4c 24 14 8b 44 24 10 33 cb 33 c1 89 44 24 90 01 01 2b f0 8b 44 24 24 29 44 24 18 ff 4c 24 1c 0f 85 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}