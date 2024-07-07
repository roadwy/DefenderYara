
rule Ransom_Win32_StopCrypt_MKSC_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.MKSC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {c1 e8 05 89 44 24 90 01 01 c7 05 90 01 08 8b 44 24 90 01 01 01 44 24 90 01 01 8b 54 24 90 01 01 8b ce e8 90 00 } //1
		$a_03_1 = {89 0c 24 c7 44 24 90 01 05 8b 44 24 90 01 01 01 44 24 90 01 01 8b 44 24 90 01 01 31 04 24 8b 04 24 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}