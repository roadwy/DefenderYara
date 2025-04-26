
rule Ransom_Win32_StopCrypt_SA_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.SA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b d0 d3 ea 8d 4c 24 ?? 89 54 24 ?? 8b 54 24 ?? e8 ?? ?? ?? ?? 8b 4c 24 ?? 33 4c 24 ?? 8b 54 24 ?? 33 d1 8d 4c 24 ?? 89 54 24 ?? 89 3d } //1
		$a_03_1 = {d3 ee c7 05 ?? ?? ?? ?? ee 3d ea f4 03 74 24 ?? 8b 44 24 ?? 31 44 24 ?? 33 74 24 ?? 83 3d ?? ?? ?? ?? 0c 89 74 24 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}