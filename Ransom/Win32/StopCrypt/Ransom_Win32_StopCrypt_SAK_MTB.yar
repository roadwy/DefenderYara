
rule Ransom_Win32_StopCrypt_SAK_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.SAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b c6 8d 4c 24 ?? e8 ?? ?? ?? ?? 01 7c 24 ?? 89 6c 24 ?? 8b 44 24 ?? 01 44 24 ?? 8b 44 24 ?? ?? 01 44 24 ?? 8b 44 24 } //1
		$a_03_1 = {8b c6 d3 e8 8b 4c 24 ?? 31 4c 24 ?? 03 c3 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 89 44 24 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}