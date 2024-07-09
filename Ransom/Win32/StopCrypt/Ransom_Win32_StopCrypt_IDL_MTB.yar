
rule Ransom_Win32_StopCrypt_IDL_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.IDL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {33 ff 89 74 24 1c 89 3d ?? ?? ?? ?? 8b 44 24 1c 01 05 ?? ?? ?? ?? a1 ?? ?? ?? ?? 89 44 24 2c 89 7c 24 1c 8b 44 24 2c 01 44 24 1c 8b 44 24 14 33 44 24 1c 89 44 24 1c 8b 4c 24 1c } //1
		$a_03_1 = {33 c6 89 44 24 14 8b 44 24 1c 31 44 24 14 a1 ?? ?? ?? ?? 2b 5c 24 14 3d 93 00 00 00 74 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}