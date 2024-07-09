
rule Ransom_Win32_StopCrypt_MKSC_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.MKSC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {c1 e8 05 89 44 24 ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 8b 44 24 ?? 01 44 24 ?? 8b 54 24 ?? 8b ce e8 } //1
		$a_03_1 = {89 0c 24 c7 44 24 ?? ?? ?? ?? ?? 8b 44 24 ?? 01 44 24 ?? 8b 44 24 ?? 31 04 24 8b 04 24 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}