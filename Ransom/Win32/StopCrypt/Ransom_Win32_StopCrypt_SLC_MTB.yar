
rule Ransom_Win32_StopCrypt_SLC_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.SLC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b d6 d3 ea 89 54 24 ?? 8b 44 24 ?? 01 44 24 ?? 8b 44 24 ?? 33 44 24 ?? 89 3d ?? ?? ?? ?? 31 44 24 ?? 8b 44 24 ?? 29 44 24 } //1
		$a_03_1 = {c1 e8 05 89 44 24 ?? 8b 44 24 ?? 01 44 24 ?? c7 05 ?? ?? ?? ?? ee 3d ea f4 8b 44 24 ?? 31 44 24 ?? 8b 4c 24 ?? 31 4c 24 ?? 83 3d } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}