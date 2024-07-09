
rule Ransom_Win32_StopCrypt_SC_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.SC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {d3 e8 89 44 24 ?? 8b 44 24 ?? 01 44 24 ?? 8b 4c 24 ?? 33 4c 24 ?? 8b 44 24 ?? 33 c1 2b f0 ba ?? ?? ?? ?? 8d 4c 24 ?? 89 44 24 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}