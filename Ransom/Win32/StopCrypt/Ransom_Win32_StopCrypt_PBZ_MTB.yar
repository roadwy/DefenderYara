
rule Ransom_Win32_StopCrypt_PBZ_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.PBZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b ce c1 e9 05 03 4d ?? 03 fb 03 c6 33 cf 33 c8 89 45 ?? 89 4d ?? 8b 45 ?? 01 05 ?? ?? ?? ?? 8b 45 ?? 29 45 ?? 8b 4d ?? c1 e1 04 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}