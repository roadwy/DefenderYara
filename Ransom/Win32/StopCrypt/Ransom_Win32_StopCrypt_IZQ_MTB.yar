
rule Ransom_Win32_StopCrypt_IZQ_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.IZQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {51 c7 04 24 ?? ?? ?? ?? 8b 44 24 ?? 83 2c 24 04 01 ?? 24 8b 04 24 31 01 } //1
		$a_03_1 = {8b d7 c1 ea ?? 8d 34 2f c7 05 ?? ?? ?? ?? ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 54 24 ?? 8b 44 24 ?? 01 44 24 18 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 75 ?? 8d 44 24 ?? 50 68 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 8b 4c 24 ?? 8b 44 24 ?? 33 ce 33 c1 2b d8 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 89 44 24 ?? 75 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}