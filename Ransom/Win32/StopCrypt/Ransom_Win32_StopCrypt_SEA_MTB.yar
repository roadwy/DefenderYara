
rule Ransom_Win32_StopCrypt_SEA_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.SEA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b c6 c1 e8 ?? 03 c5 33 44 24 ?? 33 c8 8d 44 24 ?? 89 4c 24 } //1
		$a_03_1 = {33 d2 8b 4c 24 ?? 33 4c 24 ?? 2b f1 8b c6 8d 4c 24 ?? 89 74 24 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}