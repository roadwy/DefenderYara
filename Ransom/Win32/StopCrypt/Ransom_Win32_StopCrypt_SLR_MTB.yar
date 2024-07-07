
rule Ransom_Win32_StopCrypt_SLR_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.SLR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b d7 d3 ea 89 54 24 90 01 01 8b 44 24 90 01 01 01 44 24 90 01 01 8b 54 24 90 01 01 8b ce e8 90 01 04 33 44 24 90 01 01 89 1d 90 01 04 89 44 24 90 01 01 8b 44 24 90 01 01 29 44 24 90 01 01 ba 90 01 04 8d 4c 24 90 00 } //1
		$a_03_1 = {83 ec 0c 89 54 24 90 01 01 89 0c 24 c7 44 24 04 90 01 04 8b 44 24 90 01 01 01 44 24 90 01 01 8b 44 24 90 01 01 31 04 24 8b 04 24 83 c4 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}