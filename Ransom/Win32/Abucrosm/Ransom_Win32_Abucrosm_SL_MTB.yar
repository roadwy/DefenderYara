
rule Ransom_Win32_Abucrosm_SL_MTB{
	meta:
		description = "Ransom:Win32/Abucrosm.SL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b d8 8b 45 ?? 89 18 8b 45 ?? 03 45 ?? 03 45 ?? 03 45 ?? 89 45 ?? 6a ?? e8 ?? ?? ?? ?? 8b 5d ?? 2b d8 6a ?? e8 ?? ?? ?? ?? 03 d8 8b 45 ?? 31 18 83 45 ?? ?? 83 45 ?? ?? 8b 45 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}