
rule Ransom_Win32_StopCrypt_SAL_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.SAL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b c6 89 74 24 90 01 01 e8 90 01 04 01 5c 24 90 01 01 c7 44 24 90 01 05 8b 44 24 90 01 01 01 44 24 90 01 01 8b 44 24 90 00 } //1
		$a_03_1 = {8b c6 c1 e8 90 01 01 03 c5 89 44 24 90 01 01 8b 44 24 90 01 01 31 44 24 90 01 01 8b 4c 24 90 01 01 33 4c 24 90 01 01 8d 44 24 90 01 01 89 4c 24 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}