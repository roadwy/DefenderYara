
rule Ransom_Win32_StopCrypt_SAL_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.SAL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b c6 89 74 24 ?? e8 ?? ?? ?? ?? 01 5c 24 ?? c7 44 24 ?? ?? ?? ?? ?? 8b 44 24 ?? 01 44 24 ?? 8b 44 24 } //1
		$a_03_1 = {8b c6 c1 e8 ?? 03 c5 89 44 24 ?? 8b 44 24 ?? 31 44 24 ?? 8b 4c 24 ?? 33 4c 24 ?? 8d 44 24 ?? 89 4c 24 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}