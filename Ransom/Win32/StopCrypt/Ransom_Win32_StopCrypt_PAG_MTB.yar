
rule Ransom_Win32_StopCrypt_PAG_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.PAG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 45 08 8b 45 f0 83 25 ?? ?? ?? ?? ?? 03 c8 33 4d 08 33 4d 0c 89 4d 08 8b 45 08 01 05 ?? ?? ?? ?? 2b 7d 08 89 7d fc 8b 45 fc 03 45 f8 89 45 0c } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Ransom_Win32_StopCrypt_PAG_MTB_2{
	meta:
		description = "Ransom:Win32/StopCrypt.PAG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b c7 c1 e8 05 03 44 24 ?? 03 cd 33 c1 8d 0c 3b 33 c1 2b f0 8b d6 c1 e2 04 89 44 24 14 c7 05 } //10
		$a_03_1 = {33 cb 33 c1 2b f8 8d 44 24 1c e8 ?? ?? ?? ?? ff 4c 24 18 0f 85 } //1
		$a_03_2 = {33 d3 33 c2 2b f8 8d 44 24 1c e8 ?? ?? ?? ?? ff 4c 24 18 0f 85 } //1
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=11
 
}