
rule Ransom_Win32_StopCrypt_HAB_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.HAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b d7 d3 ea c7 05 ?? ?? ?? ?? ee 3d ea f4 03 55 d8 8b 45 ec 31 45 fc 33 55 fc 89 55 d4 8b 45 d4 83 45 f8 64 29 45 f8 83 6d f8 64 8b 45 f8 } //1
		$a_03_1 = {01 45 f0 8b 45 f0 89 45 ec 8b 4d f4 8b 75 f8 d3 ee 8b 4d ec 31 4d fc 03 75 cc 81 3d ?? ?? ?? ?? 03 0b 00 00 75 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}