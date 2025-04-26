
rule Ransom_Win32_StopCrypt_SLJ_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.SLJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 4c 24 20 d3 e8 89 44 24 ?? 8b 44 24 ?? 01 44 24 ?? 33 54 24 ?? 8d 4c 24 ?? 89 54 24 } //1
		$a_03_1 = {8b 44 24 2c c1 e8 05 89 44 24 ?? c7 05 ?? ?? ?? ?? ee 3d ea f4 8b 44 24 ?? 01 44 24 ?? 33 74 24 ?? 31 74 24 ?? 83 3d } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}