
rule Ransom_Win32_StopCrypt_GHE_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.GHE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {33 c1 89 54 24 18 89 44 24 10 89 1d 90 01 04 8b 44 24 18 01 05 90 01 04 8b 15 90 01 04 89 54 24 28 89 5c 24 18 8b 44 24 28 01 44 24 18 8b 44 24 10 33 44 24 18 89 44 24 18 8b 44 24 18 90 00 } //1
		$a_03_1 = {31 5c 24 10 8b 44 24 18 31 44 24 10 a1 90 01 04 2b 74 24 10 3d 93 00 00 00 74 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}