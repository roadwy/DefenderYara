
rule Ransom_Win32_StopCrypt_SY_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.SY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {d3 e2 89 3d ?? ?? ?? ?? 03 55 ?? 33 55 ?? 33 d6 89 55 ?? 8b 45 ?? 29 45 ?? 8d 45 ?? e8 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}