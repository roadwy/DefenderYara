
rule Ransom_Win32_Ryuk_C_MTB{
	meta:
		description = "Ransom:Win32/Ryuk.C!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {0b 0b 00 00 75 90 09 33 00 8b 4d ?? 2b 4d ?? 89 4d ?? 8b 55 ?? c1 e2 04 89 55 ?? 8b 45 ?? 03 45 ?? 89 45 ?? 8b 4d ?? 03 4d ?? 89 4d ?? 8b 55 ?? c1 ea 05 89 55 ?? 81 3d } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}