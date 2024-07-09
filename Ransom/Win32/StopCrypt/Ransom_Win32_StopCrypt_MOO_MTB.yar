
rule Ransom_Win32_StopCrypt_MOO_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.MOO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b d0 c1 ea 05 03 54 24 20 03 c5 33 d1 33 d0 2b fa 8b cf c1 e1 04 81 3d ?? ?? ?? ?? 8c 07 00 00 c7 05 ?? ?? ?? ?? 00 00 00 00 89 4c 24 10 75 } //1
		$a_03_1 = {33 f3 31 74 24 10 8b 44 24 10 29 44 24 14 81 3d 4c 1c 2e 02 93 00 00 00 75 ?? 68 ?? ?? ?? ?? 8d 44 24 78 50 ff 15 ?? ?? ?? ?? eb } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}