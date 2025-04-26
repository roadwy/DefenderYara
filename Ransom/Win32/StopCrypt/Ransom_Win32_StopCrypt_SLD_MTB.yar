
rule Ransom_Win32_StopCrypt_SLD_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.SLD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {d3 e8 89 44 24 ?? 8b 44 24 ?? 01 44 24 ?? 8b 4c 24 ?? 33 4c 24 ?? 89 35 ?? ?? ?? ?? 31 4c 24 ?? 8b 44 24 ?? 29 44 24 ?? 8b 44 24 ?? 29 44 24 ?? ff 4c 24 } //1
		$a_03_1 = {c1 e8 05 89 44 24 ?? 8b 54 24 ?? 01 54 24 ?? c7 05 ?? ?? ?? ?? ee 3d ea f4 8b 44 24 ?? 31 44 24 ?? 8b 44 24 ?? 31 44 24 ?? 83 3d } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}