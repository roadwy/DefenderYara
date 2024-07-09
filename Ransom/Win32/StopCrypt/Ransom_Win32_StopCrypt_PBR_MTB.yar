
rule Ransom_Win32_StopCrypt_PBR_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.PBR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {d3 e8 89 45 ?? 8b 45 ?? 01 45 ?? 8b 5d ?? c1 e3 04 03 5d ?? 33 5d ?? 81 3d [0-0a] 75 ?? 33 c0 50 50 50 ff 15 ?? ?? ?? ?? 8b 45 ?? 83 25 [0-08] 33 c3 2b f8 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}