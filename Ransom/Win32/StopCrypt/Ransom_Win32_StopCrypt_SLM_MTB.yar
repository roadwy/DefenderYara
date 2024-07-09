
rule Ransom_Win32_StopCrypt_SLM_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.SLM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {d3 e8 89 44 24 ?? 8b 44 24 ?? 01 44 24 ?? 8b 4c 24 ?? 33 4c 24 ?? 89 3d ?? ?? ?? ?? 33 d1 } //1
		$a_03_1 = {c7 44 24 04 ?? ?? ?? ?? 8b 44 24 ?? 01 44 24 ?? 8b 44 24 ?? 31 04 24 8b 04 24 83 c4 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}