
rule Ransom_Win32_StopCrypt_SLV_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.SLV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {33 44 24 10 89 2d ?? ?? ?? ?? 89 44 24 ?? 8b 44 24 ?? 29 44 24 ?? 81 c3 ?? ?? ?? ?? ff 4c 24 ?? 89 5c 24 } //1
		$a_03_1 = {89 44 24 18 8b 44 24 ?? 01 44 24 ?? 8b 44 24 ?? c1 e8 ?? 89 44 24 ?? c7 05 ?? ?? ?? ?? ee 3d ea f4 8b 44 24 ?? 01 44 24 ?? 8b 54 24 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}