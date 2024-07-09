
rule Ransom_Win32_StopCrypt_PBX_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.PBX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c3 d3 e8 89 44 24 ?? 8b 44 24 ?? 01 44 24 ?? 8b cb c1 e1 04 03 4c 24 ?? 89 15 ?? ?? ?? ?? 33 4c 24 ?? 33 4c 24 ?? 2b f9 89 7c 24 ?? 8b 44 24 ?? 29 44 24 ?? ff 4c 24 ?? 0f 85 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}