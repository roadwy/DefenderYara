
rule Ransom_Win32_StopCrypt_SLT_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.SLT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b f7 d3 e6 89 5c 24 ?? 03 74 24 ?? 8b 44 24 ?? 01 44 24 ?? 8b 44 24 ?? 01 44 24 ?? 8b 44 24 ?? 89 44 24 ?? 8b 4c 24 ?? 8b d7 d3 ea 89 54 24 ?? 8b 44 24 ?? 01 44 24 } //1
		$a_03_1 = {33 44 24 10 89 1d ?? ?? ?? ?? 89 44 24 ?? 8b 44 24 ?? 29 44 24 ?? 81 44 24 28 ?? ?? ?? ?? 4d } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}