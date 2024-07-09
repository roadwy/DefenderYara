
rule Ransom_Win32_StopCrypt_SAI_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.SAI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c6 c1 e0 ?? 89 45 ?? 8b 45 ?? 01 45 ?? 8b 4d ?? 83 0d ?? ?? ?? ?? ?? 8b c6 c1 e8 ?? 03 45 ?? 03 ce 33 c8 31 4d ?? 2b 7d ?? c7 05 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}