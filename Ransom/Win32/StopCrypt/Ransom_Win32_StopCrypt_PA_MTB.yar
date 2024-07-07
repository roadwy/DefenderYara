
rule Ransom_Win32_StopCrypt_PA_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {c1 e0 04 89 01 c3 31 08 c3 33 44 24 04 c2 04 00 81 00 cc 36 ef c6 c3 01 08 c3 } //1
		$a_03_1 = {2b 5d fc 89 75 ec 25 90 02 04 81 6d ec 90 02 04 81 45 ec 90 02 04 8b 4d 90 02 02 8b c3 c1 e8 05 89 45 90 01 01 8d 45 90 01 01 e8 90 02 04 8b 45 90 01 01 8b 4d 90 01 01 03 c3 50 8b c3 d3 e0 03 45 90 01 01 e8 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}