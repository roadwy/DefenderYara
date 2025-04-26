
rule Ransom_Win32_StopCrypt_SAA_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.SAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {d3 ea 03 c6 89 45 ?? 03 55 ?? 8b 45 ?? 31 45 ?? 31 55 ?? 89 3d ?? ?? ?? ?? 8b 45 ?? 89 45 ?? 8b 45 ?? 29 45 ?? 8b 45 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}