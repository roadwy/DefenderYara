
rule Ransom_Win32_StopCrypt_PCG_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.PCG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {c1 e8 05 89 44 24 ?? 8b 44 24 ?? 33 74 24 ?? 03 44 24 ?? c7 05 ?? ?? ?? ?? ee 3d ea f4 33 c6 83 3d ?? ?? ?? ?? 0c 89 44 24 ?? 0f 85 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}