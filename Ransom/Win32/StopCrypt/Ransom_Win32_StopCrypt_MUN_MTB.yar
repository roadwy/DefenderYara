
rule Ransom_Win32_StopCrypt_MUN_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.MUN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b c7 c1 e8 05 03 44 24 28 03 cd 33 c1 8d 0c 3b 33 c1 2b f0 8b d6 c1 e2 04 89 44 24 14 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 54 24 } //1
		$a_03_1 = {33 d3 33 c2 2b f8 8d 44 24 1c e8 ?? ?? ?? ?? ff 4c 24 18 0f 85 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}