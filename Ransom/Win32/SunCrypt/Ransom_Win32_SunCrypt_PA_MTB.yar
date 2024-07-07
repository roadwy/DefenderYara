
rule Ransom_Win32_SunCrypt_PA_MTB{
	meta:
		description = "Ransom:Win32/SunCrypt.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {33 d2 c6 45 90 01 02 c6 45 90 01 02 c6 45 90 01 02 c6 45 90 01 02 c6 45 90 01 02 c6 45 90 01 02 c6 45 90 01 02 c6 45 90 01 02 c6 45 90 01 02 8a 45 90 01 01 c6 45 90 01 02 66 0f 1f 44 90 01 02 8a 44 90 01 02 0f be 4d 90 01 01 0f be c0 33 c1 88 44 15 90 01 01 42 83 fa 90 01 01 72 90 00 } //1
		$a_03_1 = {8b d0 c7 45 90 02 06 8b 45 90 01 01 03 c2 8a 4c 30 90 01 01 8b 45 90 01 01 32 0a 03 c7 88 0c 10 42 83 6d 90 01 02 75 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}