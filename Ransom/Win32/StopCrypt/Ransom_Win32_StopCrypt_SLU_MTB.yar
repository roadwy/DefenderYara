
rule Ransom_Win32_StopCrypt_SLU_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.SLU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b ca 8b c2 c1 e8 ?? c1 e1 ?? 03 4d ?? 03 c3 33 c1 33 45 ?? 89 45 ?? 8b 45 ?? 01 05 ?? ?? ?? ?? 8b 45 ?? 29 45 ?? 8b 45 ?? c1 e0 ?? 03 c7 89 45 ?? 8b 45 ?? 03 45 } //1
		$a_03_1 = {8b 45 0c 01 45 ?? 83 6d fc ?? 8b 45 ?? 8b 4d ?? 31 08 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}