
rule Ransom_Win32_CerberCrypt_PA_MTB{
	meta:
		description = "Ransom:Win32/CerberCrypt.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {5c 74 65 73 74 37 5c 90 02 10 5c 74 65 73 74 37 2e 70 64 62 90 00 } //1
		$a_03_1 = {83 c0 01 89 45 90 01 01 81 7d 90 02 06 7d 90 01 01 8b 45 90 01 01 99 b9 90 01 04 f7 f9 85 d2 74 90 01 01 0f b7 05 90 01 04 05 c7 90 02 03 8b 0d 90 01 04 03 4d 90 01 01 0f be 11 33 d0 a1 90 01 04 03 45 90 01 01 88 10 eb 90 01 01 0f b7 90 01 05 05 c9 90 02 03 8b 0d 90 01 04 03 4d 90 01 01 0f be 11 33 d0 a1 90 01 04 03 45 90 01 01 88 10 eb 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}