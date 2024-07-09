
rule Ransom_Win32_StopCrypt_SLZ_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.SLZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 4c 24 30 33 4c 24 ?? 89 35 ?? ?? ?? ?? 31 4c 24 ?? 8b 44 24 ?? 29 44 24 } //1
		$a_03_1 = {d3 ea c7 05 ?? ?? ?? ?? ee 3d ea f4 03 54 24 ?? 8b 44 24 ?? 31 44 24 ?? 33 54 24 ?? 83 3d ?? ?? ?? ?? 0c 89 54 24 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}